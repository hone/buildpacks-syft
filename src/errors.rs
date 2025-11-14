#[derive(thiserror::Error, Debug)]
pub enum SyftBuildpackError {
    #[error("HTTP error: {0}")]
    Reqwest(reqwest::Error),
    #[error("IO error: {0}")]
    Io(std::io::Error),
}

impl From<SyftBuildpackError> for libcnb::Error<SyftBuildpackError> {
    fn from(e: SyftBuildpackError) -> Self {
        libcnb::Error::BuildpackError(e)
    }
}
