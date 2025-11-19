use libcnb::{
    build::BuildContext,
    data::{layer_name, sbom::SbomFormat},
    layer::{
        CachedLayerDefinition, InvalidMetadataAction, LayerRef, LayerState, RestoredLayerAction,
    },
    sbom::Sbom,
};
use libherokubuildpack::inventory::{
    artifact::{Arch, Artifact, Os},
    Inventory,
};
use semver::{Version, VersionReq};
use sha2::{Digest, Sha256};

use std::{fs, os::unix::fs::PermissionsExt};

use crate::{errors::SyftBuildpackError, SyftBuildpack};

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub(crate) struct SyftLayerMetadata {
    version: Version,
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

    let artifact = detect_version()?;

    match layer_ref.state {
        LayerState::Empty { .. } => {
            download_syft(&layer_ref, &artifact)?;
        }
        LayerState::Restored { .. } => {}
    }

    write_sbom(&layer_ref, &artifact)?;

    Ok(layer_ref)
}

fn detect_version() -> libcnb::Result<Artifact<Version, Sha256, Option<()>>, SyftBuildpackError> {
    let inventory = include_str!("../../inventories/packages.toml")
        .parse::<Inventory<Version, Sha256, Option<()>>>()
        .map_err(SyftBuildpackError::ParseInventoryError)?;

    let os = std::env::consts::OS
        .parse::<Os>()
        .expect("OS should always parse.");
    let arch = std::env::consts::ARCH
        .parse::<Arch>()
        .expect("ARCH should always parse.");

    Ok(inventory
        .resolve(os, arch, &semver::VersionReq::STAR)
        .ok_or(SyftBuildpackError::NoValidArtifacts)?
        .clone())
}

fn download_syft(
    layer_ref: &LayerRef<SyftBuildpack, (), ()>,
    artifact: &Artifact<Version, Sha256, Option<()>>,
) -> libcnb::Result<(), SyftBuildpackError> {
    println!("---> Downloading Syft v{}", artifact.version);

    let response = reqwest::blocking::get(&artifact.url).map_err(SyftBuildpackError::Reqwest)?;
    let tar_gz = response.bytes().map_err(SyftBuildpackError::Reqwest)?;

    let checksum = sha2::Sha256::digest(&tar_gz);
    if checksum.to_vec() != artifact.checksum.value {
        println!("---> syft artifact checksum did not match");
        return Err(SyftBuildpackError::ChecksumMismatch)?;
    }

    let tar = flate2::read::GzDecoder::new(&tar_gz[..]);
    let mut archive = tar::Archive::new(tar);

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
        version: artifact.version.clone(),
    })?;

    Ok(())
}

fn write_sbom(
    layer_ref: &LayerRef<SyftBuildpack, (), ()>,
    syft_artifact: &Artifact<Version, Sha256, Option<()>>,
) -> libcnb::Result<(), SyftBuildpackError> {
    let inventory = include_str!("../../inventories/sboms.toml")
        .parse::<Inventory<Version, Sha256, Option<()>>>()
        .map_err(SyftBuildpackError::ParseInventoryError)?;
    let version_req = VersionReq::parse(format!("={}", syft_artifact.version).as_str())
        .expect("Failed to parse version requirement from exact version string");
    let sbom_artifact = inventory
        .resolve(syft_artifact.os, syft_artifact.arch, &version_req)
        .ok_or(SyftBuildpackError::NoValidArtifacts)?;
    let mut response =
        reqwest::blocking::get(&sbom_artifact.url).map_err(SyftBuildpackError::Reqwest)?;

    let tmpdir = tempfile::tempdir().map_err(SyftBuildpackError::Io)?;
    let syft_sbom = tmpdir.path().join("syft.sbom.syft.json");
    let mut syft_sbom_file = fs::File::create(&syft_sbom).map_err(SyftBuildpackError::Io)?;
    response
        .copy_to(&mut syft_sbom_file)
        .map_err(SyftBuildpackError::Reqwest)?;

    let mut sboms = [SbomFormat::CycloneDxJson, SbomFormat::SpdxJson]
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
    sboms.push(Sbom {
        format: SbomFormat::SyftJson,
        data: fs::read(&syft_sbom).map_err(SyftBuildpackError::Io)?,
    });

    layer_ref.write_sboms(&sboms)?;

    Ok(())
}
