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

use crate::acceptstore;
use crate::noconnector;

//use ureq::minerva;

use http::Method;

#[derive(PartialEq, Debug)]
pub struct JoinProxyInfo {
    url:  Url,
    addrs: VecDeque<SocketAddr>
}



// Custom error for JoinProxyInfo.
pub enum JoinProxyInfoError {
    NoCertificateFound,
    UreqError(ureq::Error),
    NotImplementedYet
}

// Implement std::fmt::Display for AppError
impl fmt::Display for JoinProxyInfoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JoinProxyInfoError::NoCertificateFound => {
                write!(f, "No Certificate Found")
            },
            JoinProxyInfoError::NotImplementedYet => {
                write!(f, "No implementation yet!")
            },
            JoinProxyInfoError::UreqError(error) => {
                write!(f, "UREQ error {}", error)
            }
        }
    }
}

// Implement std::fmt::Debug for AppError
impl fmt::Debug for JoinProxyInfoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JoinProxyInfoError::NoCertificateFound => {
                write!(f, "No Certificate Found")
            },
            JoinProxyInfoError::NotImplementedYet => {
                write!(f, "No implementation yet!")
            },
            JoinProxyInfoError::UreqError(error) => {
                write!(f, "UREQ error {}", error)
            }
        }
    }
}
impl From<ureq::Error> for JoinProxyInfoError {
    fn from(kind: ureq::Error) -> Self {
        Self::UreqError(kind)
    }
}

impl JoinProxyInfo {
    fn connect_one(self: &mut Self,
                   addr:   SocketAddr) -> Result<(), JoinProxyInfoError> {

        let mut _buf = [0u8; 256];

        // This is how we narrow down the allowed TLS versions for rustls.
        let protocol_versions = &[&TLS12, &TLS13];
        let verifier = Arc::new(acceptstore::AcceptAndStoreAll::empty());
        let rustls_config = Arc::new(rustls::ClientConfig::builder_with_provider(provider::default_provider().into())
                                     .with_protocol_versions(protocol_versions)
                                     .unwrap()
                                     .dangerous()
                                     .with_custom_certificate_verifier(verifier.clone())
                                     .with_no_client_auth());

        let ureq_config = ureq::tls::TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .unversioned_rustls_client_config(rustls_config)
            .build();

        //let hostname = addr.ip().to_string();
        let authority = Authority::from_sockaddr(addr).unwrap();
        println!("using hostname: {:?}", authority.to_string());
        let uri = Builder::new()
            .scheme("https")
            .authority(authority.clone())
            .path_and_query("/.well-known/brski/requestvoucher")
            .build()
            .unwrap();

        let config = Agent::config_builder().tls_config(ureq_config).build();

        /* establish the connection */
        println!("connecting to hostname: {:?}", authority.to_string());
        let conn = TcpStream::connect(addr).unwrap();
        println!("connected {:?}", conn);

        let noconnector = noconnector::NoConnector::new(conn);
        let rtls_connnector= RustlsConnector::default();
        //let connector = ().chain(rtls_connnector)
        //    .chain(noconnector);
        let connector = noconnector.chain(rtls_connnector);

        println!("starting the TLS bits with {:?}", connector);
        let agent = Agent::with_parts(config,
                                      connector,
                                      DefaultResolver::default());

        let req = agent.post(&uri.to_string());
        req.prime().unwrap();

        /* now pull the certificate from the provisional TLS verifier */
        //let certificate = https_stream.get_peer_certificate().unwrap();
        let registrar_cert = {
            let l_ee_cert = verifier.ee_cert.lock().unwrap();
            println!("fetching certificate {:?}", l_ee_cert);

            if let Some(cert1) = l_ee_cert.clone() {
                // now we have the peer certificate copied into cert1 as Arc<>
                cert1.clone()
            } else {
                return Err(JoinProxyInfoError::NoCertificateFound);
            }
        };

        println!("cert1: {:?}", registrar_cert);

        #[cfg(_YES_)]
        { //--------
            let mut vrq = Voucher::new_vrq();

            vrq.set(Attr::Assertion(Assertion::Proximity))
                .set(Attr::CreatedOn(1599086034))
                .set(Attr::SerialNumber(b"00-D0-E5-F2-00-02".to_vec()));

            // This is required when the `Sign` trait is backed by mbedtls v3.
            //init_psa_crypto();

            vrq.sign(KEY_PEM_F2_00_02, SignatureAlgorithm::ES256).unwrap();

            let _cbor = vrq.serialize().unwrap();

            return Err(JoinProxyInfoError::NotImplementedYet);

        }


        /* print it */

        /* now send a request */
        //brski_request(stream).
        //let resp = parse_response(agent, req)?;

        //println!("status code {}", resp.status().as_u16());
        //println!("response {:?}", resp);
        println!("closed");
        Ok(())
    }

    pub fn connect(self: &mut Self) -> Result<(), std::io::Error> {

        while let Some(addr) = self.addrs.pop_front() {
            println!("found address: {:?}", addr.to_string());
            let tlserr = self.connect_one(addr);

            // examine tlserr for ECONN refused and try next IP.
            match tlserr {
                Err(_x) => { return Err(std::io::Error::new(io::ErrorKind::Other, "TLS failed")) }
                Ok(_x)  => { return Ok(()) }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct BootstrapState {
    registrars: Sender<JoinProxyInfo>
}

impl BootstrapState {
    pub fn empty(sender: Sender<JoinProxyInfo>) -> Self {
        BootstrapState { registrars: sender }
    }
    pub fn channel() -> (Sender<JoinProxyInfo>, Receiver<JoinProxyInfo>) {
        channel::<JoinProxyInfo>()
    }

    pub fn addr2sockaddr(hosts: Vec<IpAddr>, port: u16) -> VecDeque<SocketAddr> {
        let mut vq = VecDeque::new();
        for h in hosts {
            vq.push_back(SocketAddr::new(h, port))
        }
        vq
    }

    pub fn add_registrar_by_url(self: &mut Self, url: Url) -> Result<(), std::io::Error> {

        let hostname = url.host_str().unwrap();
        let maybeport= url.port();
        let defport = match url.scheme() {
            "https" => 443,
            "coaps" => 5684,
            _ => { return Err ( std::io::Error::from(std::io::ErrorKind::Other)) }
        };
        let port = match maybeport {
            None => { defport },
            Some(x) => x
        };
        let hosts = lookup_host(hostname)?;
        self.registrars.send(JoinProxyInfo {
            url:   url,
            addrs: BootstrapState::addr2sockaddr(hosts, port)
        }).unwrap();
        Ok(())
    }

    pub fn add_registrar_by_ip(self: &mut Self, ip: std::net::IpAddr, port: u16) -> Result<(), std::io::Error> {

        let mut url = Url::from_file_path("/.well-known/brski/request/voucher").unwrap();
        url.set_ip_host(ip).unwrap();
        let hosts = vec![ip];
        self.registrars.send(JoinProxyInfo {
            url:   url,
            addrs: BootstrapState::addr2sockaddr(hosts, port)
        }).unwrap();
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn add_registrar_url() -> Result<(), std::io::Error> {
        let url = Url::parse("https://example.com/.well-known/brski/requestvoucher").unwrap();

        let (sender, receiver) = BootstrapState::channel();

        let mut state = BootstrapState::empty(sender);
        state.add_registrar_by_url(url)?;

        let _thing = receiver.recv().unwrap();
        Ok(())
    }

    #[test]
    fn add_registrar_ip() -> Result<(), std::io::Error> {
        let (sender, receiver) = BootstrapState::channel();
        let mut state = BootstrapState::empty(sender);

        let ipaddr = "fe80::1234".parse().unwrap();
        state.add_registrar_by_ip(ipaddr, 8443)?;

        let _thing = receiver.recv().unwrap();
        Ok(())
    }

    #[test]
    fn add_bad_registrar_url() {
        let (sender, _receiver) = BootstrapState::channel();

        let url = Url::parse("https://foobar.example/.well-known/brski/requestvoucher").unwrap();

        let mut state = BootstrapState::empty(sender);

        let ekind = state.add_registrar_by_url(url).map_err(|e| e.kind());
        assert_eq!(Err(std::io::ErrorKind::Other), ekind);
    }

}



/*
 * Local Variables:
 * mode: rust
 * compile-command: "cd .. && cargo build"
 * End:
 */
