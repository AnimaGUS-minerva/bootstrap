// This library derives from unit.rs,
// it provides the needed mechanism to do RFC8995 (BRSKI) over https

//use std::fmt::{self, Display};
//use std::io::{self, Write};

//use log::debug;

use std::net::TcpStream;
use std::time::Duration;
use std::thread::sleep;
use url::Url;
use std::sync::Arc;
//use std::sync::Mutex;
use crate::unit::Unit;
//use crate::stream::Stream;
use crate::agent::Agent;
//use crate::response::Response;
use crate::request::Request;
use crate::header::Header;
//use crate::body::{self, BodySize, Payload, SizedReader};
use crate::body::{Payload};
use crate::error::{Error, ErrorKind};
//use crate::agent::RedirectAuthHeaders;
//use crate::connect::{connect_inner,can_propagate_authorization_on_redirect};

#[cfg(feature = "mbedtls")]
use crate::mbedtls as self_mbedtls;

use std::convert::TryFrom;

//static KEY_PEM_F2_00_02: &[u8] = core::include_bytes!(
//    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/key.pem"));

use std::io::{self, Cursor, Write};

#[cfg(feature = "minerva-mbedtls")]
