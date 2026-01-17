use anyhow::Result;
use std::mem::MaybeUninit;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use unixpcap_ebpf;

fn main() -> Result<()> {
    let mut builder = unixpcap_ebpf::UnixpcapSkelBuilder::default();
    builder.obj_builder.debug(true);

    let mut open_obj = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_obj)?;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("Capturing packets");

    loop {}
}
