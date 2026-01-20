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
    orig_data_len: u32,
}

struct CapturedPacket<'a> {
    hdr: CapturedPacketHeader,
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
        match std::str::from_utf8(&packet.data) {
            Ok(v) => println!(
                "tid={}; timestamp={}; txt={}",
                packet.hdr.tid, packet.hdr.timestamp, v
            ),
            Err(_) => println!(
                "tid={}; timestamp={}; data={:02X?}",
                packet.hdr.tid, packet.hdr.timestamp, packet.data
            ),
        };
        // Add to writer
        self.writer
            .write_packet(packet.hdr.timestamp, packet.hdr.tid, packet.hdr.orig_data_len,packet.data)?;
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
        if data.len() < 16 {
            return 0;
        }
        capture
            .process_packet(CapturedPacket {
                hdr: CapturedPacketHeader {
                    timestamp: byteorder::LittleEndian::read_u64(&data[0..8]),
                    tid: byteorder::LittleEndian::read_u32(&data[8..12]),
                    orig_data_len: byteorder::LittleEndian::read_u32(&data[12..16]),
                },
                data: &data[16..],
            })
            .unwrap();
        return 0;
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
