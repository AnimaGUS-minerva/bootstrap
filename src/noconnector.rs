/*
 * Copyright [2021] <mcr@sandelman.ca>

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

#![allow(dead_code, unused_imports)]

use std::net::{SocketAddr};
use std::net::IpAddr;
use std::net::TcpStream;
use std::fmt;
use std::sync::{Arc,Mutex};
use ureq::{Error};

//use dns_lookup::{AddrInfo, AddrInfoHints, lookup_host, getaddrinfo, SockType};
use std::collections::VecDeque;
//use std::io::{self, Write, Read};
use std::io::{self};
//use std::str;
use std::sync::mpsc::{channel,Sender,Receiver};
use dns_lookup::{lookup_host};
use url::Url;
use http::uri::{Builder, Authority};

use rustls::version::TLS12;
use rustls::version::TLS13;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::ClientConfig;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::crypto::{aws_lc_rs as provider};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls_pki_types::{CertificateDer, pem::PemObject, ServerName, UnixTime};
use ureq::unversioned::transport::RustlsConnector;
use ureq::unversioned::transport::DefaultConnector;
use ureq::unversioned::transport::NextTimeout;
use ureq::unversioned::transport::Transport;
use ureq::unversioned::transport::tcp::TcpTransport;
use ureq::unversioned::transport::Either;
use ureq::unversioned::resolver::ArrayVec;
use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::resolver::Resolver;
use ureq::unversioned::transport::time::{Instant,Duration};
use ureq::unversioned::transport::{
    Buffers, ConnectProxyConnector, ConnectionDetails, Connector, LazyBuffers, TcpConnector,
};
use ureq::tls::TlsProvider;
use ureq::tls::TlsConfig;
use ureq::Timeout;
use ureq::Agent;
use ureq;


//use ureq::minerva;

use http::Method;

// implement a Connector that does nothing
#[derive(Debug)]
pub struct NoConnector {
    pub stream: TcpStream
}

impl NoConnector {
    pub fn new(stream: TcpStream) -> Self {
        NoConnector { stream }
    }
}

impl<In: Transport> Connector<In> for NoConnector {
    type Out = Either<In, TcpTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, Error> {

        println!("NoConnector {:?} next: {:?}", self.stream, chained);

        let config = &details.config;
        let buffers = LazyBuffers::new(config.input_buffer_size(), config.output_buffer_size());
        let transport = TcpTransport::new(self.stream.try_clone().unwrap(), buffers);
        //debug!("connected");

        Ok(Some(Either::B(transport)))
    }
}

/*
 * Local Variables:
 * mode: rust
 * compile-command: "cd .. && cargo build"
 * End:
 */
