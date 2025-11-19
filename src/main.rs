use libcnb::build::{BuildContext, BuildResult, BuildResultBuilder};
use libcnb::generic::{GenericMetadata, GenericPlatform};
use libcnb::{Buildpack, buildpack_main};

mod errors;
mod layers;
use crate::errors::SyftBuildpackError;

pub(crate) struct SyftBuildpack;

impl Buildpack for SyftBuildpack {
    type Platform = GenericPlatform;
    type Metadata = GenericMetadata;
    type Error = SyftBuildpackError;

    fn detect(
        &self,
        _context: libcnb::detect::DetectContext<Self>,
    ) -> libcnb::Result<libcnb::detect::DetectResult, Self::Error> {
        libcnb::detect::DetectResultBuilder::pass().build()
    }

    fn build(&self, context: BuildContext<Self>) -> libcnb::Result<BuildResult, Self::Error> {
        println!("---> Syft Buildpack");

        let _layer_ref = layers::syft::handle(&context)?;

        BuildResultBuilder::new().build()
    }
}

buildpack_main!(SyftBuildpack);
