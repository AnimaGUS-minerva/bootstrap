/*
 * Copyright [2026] <mcr@sandelman.ca>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 *
 */

use std::fmt;
use webpki;
use ureq;
use url;
use rcgen;
use x509_cert::der;

// Custom error for JoinProxyInfo.
pub enum BsError {
    CertificateInvalidForName,
    NoCertificateFound,
    PrivateKeyUnavailable,
    UreqError(ureq::Error),
    WebpkiError(webpki::Error),
    StdError(std::io::Error),
    RcGenError(rcgen::Error),
    UrlParseError(url::ParseError),
    DerError(der::Error),
    NotImplementedYet
}

// Implement std::fmt::Display for AppError
impl fmt::Display for BsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BsError::CertificateInvalidForName => {
                write!(f, "Invalid For Name")
            },
            BsError::NoCertificateFound => {
                write!(f, "No Certificate Found")
            },
            BsError::PrivateKeyUnavailable => {
                write!(f, "No Private key available for CSR")
            },
            BsError::NotImplementedYet => {
                write!(f, "No implementation yet!")
            },
            BsError::UreqError(error) => {
                write!(f, "UREQ error {}", error)
            },
            BsError::WebpkiError(error) => {
                write!(f, "Webpki error {}", error)
            },
            BsError::StdError(error) => {
                write!(f, "Std error {}", error)
            },
            BsError::RcGenError(error) => {
                write!(f, "RcGen Error {}", error)
            }
            BsError::UrlParseError(error) => {
                write!(f, "UrlParse Error {}", error)
            }
            BsError::DerError(error) => {
                write!(f, "DerError {}", error)
            }
        }
    }
}

// Implement std::fmt::Debug for AppError
impl fmt::Debug for BsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BsError::CertificateInvalidForName => {
                write!(f, "Certificate Invalid for Name")
            },
            BsError::NoCertificateFound => {
                write!(f, "No Certificate Found")
            },
            BsError::PrivateKeyUnavailable => {
                write!(f, "No Private key available for CSR")
            },
            BsError::NotImplementedYet => {
                write!(f, "No implementation yet!")
            },
            BsError::UreqError(error) => {
                write!(f, "UREQ error {}", error)
            },
            BsError::WebpkiError(error) => {
                write!(f, "Webpki error {}", error)
            },
            BsError::StdError(error) => {
                write!(f, "Std error {}", error)
            },
            BsError::RcGenError(error) => {
                write!(f, "RcGen error {}", error)
            }
            BsError::UrlParseError(error) => {
                write!(f, "UrlParse Error {}", error)
            }
            BsError::DerError(error) => {
                write!(f, "DerError {}", error)
            }
        }
    }
}
impl From<ureq::Error> for BsError {
    fn from(kind: ureq::Error) -> Self {
        Self::UreqError(kind)
    }
}
impl From<rcgen::Error> for BsError {
    fn from(kind: rcgen::Error) -> Self {
        Self::RcGenError(kind)
    }
}
impl From<std::io::Error> for BsError {
    fn from(kind: std::io::Error) -> Self {
        Self::StdError(kind)
    }
}
impl From<webpki::Error> for BsError {
    fn from(kind: webpki::Error) -> Self {
        Self::WebpkiError(kind)
    }
}
impl From<url::ParseError> for BsError {
    fn from(kind: url::ParseError) -> Self {
        Self::UrlParseError(kind)
    }
}
impl From<der::Error> for BsError {
    fn from(kind: der::Error) -> Self {
        Self::DerError(kind)
    }
}
