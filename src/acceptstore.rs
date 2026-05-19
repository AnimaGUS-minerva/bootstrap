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

// dummy Certificate verifier that keeps track of received certificates
#[derive(Debug)]
pub struct AcceptAndStoreAll<'a> {
    //pub listOfCertificates: Mutex<Vec<CertificateDer<'a>>>
    pub ee_cert: Mutex<Option<Arc<CertificateDer<'a>>>>
}

impl AcceptAndStoreAll<'_> {
    pub fn empty() -> Self {
        Self {
            //listOfCertificates: Mutex::new(Vec::<CertificateDer>::new())
            ee_cert: Mutex::new(None)
        }
    }
}

impl ServerCertVerifier for AcceptAndStoreAll<'_> {
    /// do nothing, but succeed, storing the end_entity certificate for later.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {

        let ee = end_entity.clone().into_owned();
        {
            let mut ee_cert = self.ee_cert.lock().unwrap();
            *ee_cert = Some(Arc::new(ee));
        }
        //{
        //  let mut list = self.listOfCertificates.lock().unwrap();
        //  list.push(ee);
        //}

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algs = provider::default_provider().signature_verification_algorithms;
        verify_tls12_signature(message, cert, dss, &algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algs = provider::default_provider().signature_verification_algorithms;
        verify_tls13_signature(message, cert, dss, &algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        provider::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn create_certificate_verifier() {
        let _verifier = AcceptAndStoreAll::empty();
    }

}



/*
 * Local Variables:
 * mode: rust
 * compile-command: "cd .. && cargo build"
 * End:
 */
