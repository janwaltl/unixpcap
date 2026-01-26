use anyhow::Result;
use byteorder::{BigEndian, LittleEndian, WriteBytesExt};
use std::io::Write;
use std::net::Ipv4Addr;

// PcapNG Writer
// Based on https://pcapng.com/
pub struct PcapNgWriter<W: Write> {
    writer: W,
    seq: u32,
}

impl<W: Write> PcapNgWriter<W> {
    pub fn new(writer: W) -> Result<Self> {
        Ok(Self { writer, seq: 0 })
    }

    pub fn write_header(&mut self) -> Result<()> {
        let mut buf = Vec::new();

        // Section Header Block (SHB)
        //Block type = SHB magic
        buf.write_u32::<LittleEndian>(0x0A0D0D0A)?;
        //Block length = 28
        buf.write_u32::<LittleEndian>(28)?;
        //Byte-order magic
        buf.write_u32::<LittleEndian>(0x1A2B3C4D)?;
        //Major version = 1
        buf.write_u16::<LittleEndian>(1)?;
        //Minor version = 0
        buf.write_u16::<LittleEndian>(0)?;
        //Section length = unknown
        buf.write_u64::<LittleEndian>(0xFFFFFFFFFFFFFFFF)?;
        //IMPROVE add SHB options here
        //Block length again
        buf.write_u32::<LittleEndian>(28)?; // Total Len Repeat

        // Interface Description Block (IDB)
        // Block type = IDB magic
        buf.write_u32::<LittleEndian>(1)?;
        // Block length = 20
        buf.write_u32::<LittleEndian>(28)?;
        // LinkType = Ethernet
        buf.write_u16::<LittleEndian>(1)?;
        // Reserved
        buf.write_u16::<LittleEndian>(0)?;
        // Snap length - max packet size = 64KB
        buf.write_u32::<LittleEndian>(65535)?;
        //Options
        // - timestamp resolution - tag
        buf.write_u16::<LittleEndian>(9)?;
        // - timestamp resolution - length
        buf.write_u16::<LittleEndian>(1)?;
        // - timestamp resolution - nanoseconds + 3 bytes of padding
        buf.write_u32::<LittleEndian>(9)?;

        // Block length again
        buf.write_u32::<LittleEndian>(28)?;

        self.writer.write_all(&buf)?;
        self.writer.flush()?;
        Ok(())
    }

    pub fn write_packet(
        &mut self,
        timestamp_ns: u64,
        tid: u32,
        orig_len: usize,
        data: &[u8],
    ) -> Result<()> {
        // Packet is written in EPB (see below)
        // Construct the packet before the header so we can write
        // the total length into the header.
        //
        // We report the packets as if they were UDP.

        // Ethernet (14) + IP (20) + UDP(8)
        let header_len = 14 + 20 + 8;
        let packet_len = header_len + data.len();
        let orig_packet_len = header_len + orig_len;
        // EPB requires 32bit alignment
        let padded_packet_len = (packet_len + 3) & !3;

        let mut pkt = Vec::with_capacity(packet_len);

        // Ethernet
        // Dst MAC - use thread ID
        pkt.write_u48::<BigEndian>(tid as u64)?;
        // Src MAC - use thread ID
        pkt.write_u48::<BigEndian>(tid as u64)?;
        // Type - IPv4
        pkt.write_u16::<BigEndian>(0x0800)?;

        // IP
        // Version (4) + header length (5)
        pkt.write_u8(0x45)?; // Ver+IHL
        // DSCP+ECN - just 0
        pkt.write_u8(0)?;
        // Packet length
        pkt.write_u16::<BigEndian>((orig_packet_len - 14) as u16)?;
        // IP ID
        pkt.write_u16::<BigEndian>(self.seq as u16)?; // ID
        self.seq = self.seq.wrapping_add(1);
        // Flags + Frag
        pkt.write_u16::<BigEndian>(0x4000)?;
        // TTL - pick 64
        pkt.write_u8(64)?;
        // Protocol - UDP
        pkt.write_u8(17)?;
        // Checksum - lazy so putting 0
        pkt.write_u16::<BigEndian>(0)?;
        // Src IP - use thread ID
        // IMPROVE use some socket ID and resolve it to process+path
        pkt.write_all(&Ipv4Addr::from(tid).octets())?;
        // Dst IP - use thread ID
        // IMPROVE use some socket ID and resolve it to process+path
        pkt.write_all(&Ipv4Addr::from(tid).octets())?;

        // UDP
        // Src port - use bits of thread ID
        pkt.write_u16::<BigEndian>(tid as u16)?;
        // Dst port - use bits of thread ID
        pkt.write_u16::<BigEndian>(tid as u16)?;
        // Data len - UDP header (8) + data
        pkt.write_u16::<BigEndian>((8 + orig_len) as u16)?;
        // Checksum - lazy so putting 0
        pkt.write_u16::<BigEndian>(0)?;

        pkt.write_all(data)?;
        // Padding to 32bit
        let pad = padded_packet_len - packet_len;
        for _ in 0..pad {
            pkt.write_u8(0)?;
        }

        let mut block = Vec::new();

        // Enhanced Packet Block (EPB)
        // BLock type = EPB magic
        block.write_u32::<LittleEndian>(6)?;
        // Block total length - header + packet
        let block_len = 32 + padded_packet_len as u32;
        block.write_u32::<LittleEndian>(block_len)?;
        // Interface ID - the first one
        block.write_u32::<LittleEndian>(0)?;
        // Packet metadata
        // - Timestamp (split in 2 32 bits)
        block.write_u32::<LittleEndian>((timestamp_ns >> 32) as u32)?;
        block.write_u32::<LittleEndian>((timestamp_ns & 0xFFFFFFFF) as u32)?;
        // - Captured packet length
        block.write_u32::<LittleEndian>(packet_len as u32)?;
        // - Original packet length
        block.write_u32::<LittleEndian>(orig_packet_len as u32)?;

        // Packet with metadata
        block.write_all(&pkt)?;

        // Block total length again
        block.write_u32::<LittleEndian>(block_len)?;

        self.writer.write_all(&block)?;
        self.writer.flush()?;
        Ok(())
    }
}
