use anyhow::Result;
use byteorder::ByteOrder;
use std::mem::MaybeUninit;

use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use unixpcap_ebpf;

struct CapturedPacketHeader {
    timestamp: u64,
    tid: u32,
    //data_len: u32,
}

struct CapturedPacket<'a> {
    hdr: CapturedPacketHeader,
    data: &'a [u8],
}

fn process_packet(packet: CapturedPacket) {
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
}

fn main() -> Result<()> {
    // Load the eBPF program
    let mut builder = unixpcap_ebpf::UnixpcapSkelBuilder::default();
    builder.obj_builder.debug(true);

    let mut open_obj = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_obj)?;

    let mut skel = open_skel.load()?;

    let mut packet_rb_builder = RingBufferBuilder::default();
    packet_rb_builder.add(&skel.maps.captured_packets, |data| {
        if data.len() < 16 {
            return 0;
        }
        process_packet(CapturedPacket {
            hdr: CapturedPacketHeader {
                timestamp: byteorder::LittleEndian::read_u64(&data[0..8]),
                tid: byteorder::LittleEndian::read_u32(&data[8..12]),
                //data_len: byteorder::LittleEndian::read_u32(&data[12..16]),
            },
            data: &data[16..],
        });
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
