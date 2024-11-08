use std::mem::MaybeUninit;

use crate::DescribeOpts;
use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

mod systing {
    include!(concat!(env!("OUT_DIR"), "/systing_describe.skel.rs"));
}

pub fn describe(opts: DescribeOpts) -> Result<()> {
    let mut skel_builder = systing::SystingDescribeSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    open_skel.maps.rodata_data.tool_config.tgid = opts.pid;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    Ok(())
}
