use libcnb::{
    build::BuildContext,
    data::{layer_name, sbom::SbomFormat},
    layer::{
        CachedLayerDefinition, InvalidMetadataAction, LayerRef, LayerState, RestoredLayerAction,
    },
    sbom::Sbom,
};

use std::{fs, os::unix::fs::PermissionsExt};

use crate::{errors::SyftBuildpackError, SyftBuildpack};

const SYFT_VERSION: &str = "1.34.2";
const SYFT_ARCH: &str = "amd64";

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
                "https://github.com/anchore/syft/releases/download/v{}/syft_{}_linux_{}.tar.gz",
                SYFT_VERSION, SYFT_VERSION, SYFT_ARCH
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
                    let bin_path = layer_ref.path().join("bin");
                    fs::create_dir(&bin_path).map_err(SyftBuildpackError::Io)?;
                    let syft_path = bin_path.join("syft");
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

    write_sbom(&layer_ref)?;

    Ok(layer_ref)
}

fn write_sbom(
    layer_ref: &LayerRef<SyftBuildpack, (), ()>,
) -> libcnb::Result<(), SyftBuildpackError> {
    let syft_sbom_url = format!(
        "https://github.com/anchore/syft/releases/download/v{}/syft_{}_linux_{}.sbom",
        SYFT_VERSION, SYFT_VERSION, SYFT_ARCH
    );
    let mut response =
        reqwest::blocking::get(&syft_sbom_url).map_err(SyftBuildpackError::Reqwest)?;

    let tmpdir = tempfile::tempdir().map_err(SyftBuildpackError::Io)?;
    let syft_sbom = tmpdir.path().join("syft.sbom.syft.json");
    let mut syft_sbom_file = fs::File::create(&syft_sbom).map_err(SyftBuildpackError::Io)?;
    response
        .copy_to(&mut syft_sbom_file)
        .map_err(SyftBuildpackError::Reqwest)?;

    let sboms = [SbomFormat::CycloneDxJson, SbomFormat::SpdxJson]
        .into_iter()
        .map(|format| {
            let file = if format == SbomFormat::CycloneDxJson {
                tmpdir.path().join("syft.sbom.cdx.json")
            } else {
                tmpdir.path().join("syft.sbom.spdx.json")
            };
            let o_option = if format == SbomFormat::CycloneDxJson {
                format!("cyclonedx-json={}", file.display())
            } else {
                format!("spdx-json={}", file.display())
            };
            std::process::Command::new(layer_ref.path().join("bin/syft"))
                .arg("convert")
                .arg(&syft_sbom)
                .arg("-o")
                .arg(o_option)
                .output()
                .map_err(SyftBuildpackError::Io)?;

            Ok(Sbom {
                format: format,
                data: fs::read(&file).map_err(SyftBuildpackError::Io)?,
            })
        })
        .collect::<Result<Vec<Sbom>, SyftBuildpackError>>()?;

    layer_ref.write_sboms(&sboms)?;

    Ok(())
}
