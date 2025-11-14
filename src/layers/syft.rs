use libcnb::{
    build::BuildContext,
    data::layer_name,
    layer::{
        CachedLayerDefinition, InvalidMetadataAction, LayerRef, LayerState, RestoredLayerAction,
    },
};

use std::{fs, os::unix::fs::PermissionsExt};

use crate::{errors::SyftBuildpackError, SyftBuildpack};

const SYFT_VERSION: &str = "1.34.2";

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub(crate) struct SyftLayerMetadata {
    version: String,
}

pub(crate) fn handle(
    context: &BuildContext<SyftBuildpack>,
) -> libcnb::Result<LayerRef<SyftBuildpack, (), ()>, SyftBuildpackError> {
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

    Ok(layer_ref)
}
