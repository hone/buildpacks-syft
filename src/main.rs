use libcnb::build::{BuildContext, BuildResult, BuildResultBuilder};
use libcnb::data::layer_name;
use libcnb::generic::GenericPlatform;
use libcnb::layer::{
    CachedLayerDefinition, InvalidMetadataAction, LayerState, RestoredLayerAction,
};
use libcnb::{buildpack_main, Buildpack};

use std::fs;
use std::os::unix::fs::PermissionsExt;

mod errors;
use crate::errors::SyftBuildpackError;

const SYFT_VERSION: &str = "1.34.2";

pub(crate) struct SyftBuildpack;

impl Buildpack for SyftBuildpack {
    type Platform = GenericPlatform;
    type Metadata = SyftLayerMetadata;
    type Error = SyftBuildpackError;

    fn detect(
        &self,
        _context: libcnb::detect::DetectContext<Self>,
    ) -> libcnb::Result<libcnb::detect::DetectResult, Self::Error> {
        libcnb::detect::DetectResultBuilder::pass().build()
    }

    fn build(&self, context: BuildContext<Self>) -> libcnb::Result<BuildResult, Self::Error> {
        println!("---> Syft Buildpack");
        let layer_ref = context.cached_layer(
            layer_name!("syft"),
            CachedLayerDefinition {
                build: true,
                launch: false,
                invalid_metadata_action: &|_| InvalidMetadataAction::DeleteLayer,
                restored_layer_action: &|_: &SyftLayerMetadata, _| RestoredLayerAction::KeepLayer,
            },
        )?;

        match layer_ref.state {
            LayerState::Empty { .. } => {
                println!("---> Downloading Syft v{}", SYFT_VERSION);

                let syft_url = format!(
                "https://github.com/anchore/syft/releases/download/v{}/syft_{}_linux_amd64.tar.gz",
                SYFT_VERSION, SYFT_VERSION
            );

                let response =
                    reqwest::blocking::get(&syft_url).map_err(SyftBuildpackError::Reqwest)?;
                let tar_gz = response.bytes().map_err(SyftBuildpackError::Reqwest)?;
                let tar = flate2::read::GzDecoder::new(&tar_gz[..]);
                let mut archive = tar::Archive::new(tar);

                println!("---> Extracting Syft to {}", layer_ref.path().display());
                for entry in archive.entries().map_err(SyftBuildpackError::Io)? {
                    let mut entry = entry.map_err(SyftBuildpackError::Io)?;
                    if entry.path().unwrap().ends_with("syft") {
                        let syft_path = layer_ref.path().join("syft");
                        entry.unpack(&syft_path).unwrap();
                        let mut perms = fs::metadata(&syft_path)
                            .map_err(SyftBuildpackError::Io)?
                            .permissions();
                        perms.set_mode(0o755);
                        fs::set_permissions(&syft_path, perms).map_err(SyftBuildpackError::Io)?;
                        break;
                    }
                }

                layer_ref.write_metadata(SyftLayerMetadata {
                    version: SYFT_VERSION.to_string(),
                })?;
            }
            LayerState::Restored { .. } => {}
        }

        BuildResultBuilder::new().build()
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub(crate) struct SyftLayerMetadata {
    version: String,
}

buildpack_main!(SyftBuildpack);
