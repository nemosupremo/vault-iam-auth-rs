use std::fmt;

use aws_credential_types::provider::error::CredentialsError;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct VaultError {
    errors: Vec<String>,
}

#[derive(Debug)]
pub enum Error {
    CredentialsError(CredentialsError),
    ConnectError(tokio::io::Error),
    HTTPError(hyper::Error),
    DeserializationError(serde_json::Error),
    VaultError(VaultError),
    EmptyToken,
}

impl From<CredentialsError> for Error {
    fn from(err: CredentialsError) -> Self {
        Error::CredentialsError(err)
    }
}

impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Self {
        Error::HTTPError(err)
    }
}

impl From<tokio::io::Error> for Error {
    fn from(err: tokio::io::Error) -> Self {
        Error::ConnectError(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::DeserializationError(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialsError(err) => err.fmt(f),
            Self::HTTPError(err) => err.fmt(f),
            Self::ConnectError(err) => err.fmt(f),
            Self::DeserializationError(err) => err.fmt(f),
            Self::VaultError(err) => write!(f, "Vault error: {}", err.errors.join(", ")),
            Self::EmptyToken => write!(f, "Vault error: returned token was empty"),
        }
    }
}

impl std::error::Error for Error {}
