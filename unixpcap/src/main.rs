mod pcap_writer;

use anyhow::Result;
use byteorder::ByteOrder;
use clap::Parser;
use std::fs::File;
use std::io::BufWriter;
use std::mem::MaybeUninit;

use crate::pcap_writer::PcapNgWriter;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use unixpcap_ebpf;

struct CapturedPacketHeader {
    timestamp: u64,
    tid: u32,
    orig_data_len: u16,
}

struct CapturedPacket<'a> {
    hdr: CapturedPacketHeader,
    src_path: &'a [u8],
    dst_path: &'a [u8],
    data: &'a [u8],
}

struct PcapCapture {
    writer: PcapNgWriter<BufWriter<File>>,
}
impl PcapCapture {
    pub fn new(file: &str) -> Result<Self> {
        let file = File::create(file)?;
        let writer = BufWriter::new(file);
        let mut pcap_writer = PcapNgWriter::new(writer)?;
        pcap_writer.write_header()?;

        Ok(Self {
            writer: pcap_writer,
        })
    }

    fn process_packet(&mut self, packet: CapturedPacket) -> Result<()> {
        // Print to stdout
        let txt = std::str::from_utf8(&packet.data).unwrap_or("[binary]");

        let mut dst = std::str::from_utf8(&packet.dst_path).unwrap_or("@unknown:0");
        if dst.len() == 0 {
            dst = "@unknown:0";
        }

        let mut src = std::str::from_utf8(&packet.src_path).unwrap_or("");
        let src_str;
        if src.len() == 0 {
            src_str = format!("@unbound:{}", packet.hdr.tid);
            src = src_str.as_str();
        }

        println!(
            "tid={}; timestamp={}; from={}; to={}; txt={}",
            packet.hdr.tid, packet.hdr.timestamp, src, dst, txt
        );
        // Replace src path with TID

        // Add to writer
        self.writer.write_packet(
            packet.hdr.timestamp,
            packet.hdr.tid,
            packet.hdr.orig_data_len as usize,
            src,
            dst,
            packet.data,
        )?;

        Ok(())
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Pcap file to store the capture packets into.
    name: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Load the eBPF program
    let mut builder = unixpcap_ebpf::UnixpcapSkelBuilder::default();
    builder.obj_builder.debug(true);

    let mut open_obj = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_obj)?;

    let mut skel = open_skel.load()?;

    let mut capture = PcapCapture::new(args.name.as_str())?;

    let mut packet_rb_builder = RingBufferBuilder::default();
    packet_rb_builder.add(&skel.maps.captured_packets, |data| {
        // IMPROVE automated header deserialization.
        const HEADER_SIZE: usize = 24;
        if data.len() < HEADER_SIZE {
            return 0;
        }
        if data.len() < HEADER_SIZE {
            return 0;
        }

        let src_len = byteorder::LittleEndian::read_u16(&data[14..16]) as usize;
        let dst_len = byteorder::LittleEndian::read_u16(&data[16..18]) as usize;
        let data_len = byteorder::LittleEndian::read_u16(&data[18..20]) as usize;
        let s_b: usize = HEADER_SIZE;
        let s_e = s_b + src_len;
        let d_e = s_e + dst_len;

        assert!(
            HEADER_SIZE + src_len + dst_len + data_len == data.len(),
            "malformed packet"
        );
        return capture
            .process_packet(CapturedPacket {
                hdr: CapturedPacketHeader {
                    timestamp: byteorder::LittleEndian::read_u64(&data[0..8]),
                    tid: byteorder::LittleEndian::read_u32(&data[8..12]),
                    orig_data_len: byteorder::LittleEndian::read_u16(&data[12..14]),
                },

                src_path: &data[s_b..s_e],
                dst_path: &data[s_e..d_e],
                data: &data[d_e..],
            })
            .map_or(-1, |_| 0);
    })?;

    println!("Building RB");
    let packet_rb = packet_rb_builder.build()?;
    println!("Attaching capture");
    skel.attach()?;
    println!("Capturing packets...");
    loop {
        packet_rb.poll(std::time::Duration::from_millis(100))?;
    }
}
