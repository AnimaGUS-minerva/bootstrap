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
use std::sync::Arc;
use std::time::Duration;
use ureq::{Error, ErrorKind, TlsConnector};

//use dns_lookup::{AddrInfo, AddrInfoHints, lookup_host, getaddrinfo, SockType};
use std::collections::VecDeque;
//use std::io::{self, Write, Read};
use std::io::{self};
//use std::str;
use std::sync::mpsc::{channel,Sender,Receiver};
use dns_lookup::{lookup_host};
use url::Url;
use http::uri::{Builder, Authority};
use crate::mbedtls_connector;

use crate::custom_voucher::{CustomVoucher as Voucher};
use minerva_voucher::{attr::*, SignatureAlgorithm, Sign};

use mbedtls::rng::OsEntropy;
//use mbedtls::rng::CtrDrbg;
//use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
use mbedtls::ssl::{Config, Context};
//use mbedtls::x509::Certificate;
//use mbedtls::Result as TlsResult;

//use ureq::minerva;
static KEY_PEM_F2_00_02: &[u8] = &[0u8]; // dummy

use http::Method;

#[derive(PartialEq, Debug)]
pub struct JoinProxyInfo {
    url:  Url,
    addrs: VecDeque<SocketAddr>
}

pub fn init_psa_crypto() {
    use minerva_mbedtls::psa_crypto;

    psa_crypto::init().unwrap();
    psa_crypto::initialized().unwrap();
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
        let connector = Arc::new(mbedtls_connector::MbedTlsConnector::new(mbedtls::ssl::config::AuthMode::None));

        let hostname = addr.ip().to_string();
        let authority = Authority::from_sockaddr(addr).unwrap();
        println!("using hostname: {:?}", authority.to_string());
        let uri = Builder::new()
            .scheme("https")
            .authority(authority)
            .path_and_query("/.well-known/brski/requestvoucher")
            .build()
            .unwrap();

        let agent = ureq::builder()
            .tls_connector(connector.clone())
            .timeout_connect(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build();

        /* establish the connection */
        let conn = TcpStream::connect(addr).unwrap();

        /* do the TLS bits */
        let connbox = Box::new(conn);
        let _https_stream = connector.connect(&hostname, connbox)?;
        let _request = agent.request(&"POST".to_string(), &uri.to_string());

        /* now pull the certificate out of the stream */
        //let certificate = https_stream.get_peer_certificate().unwrap();
        let _cert = {
            let mbedtls_context    = connector.context.lock().unwrap();
            let certificate_list   = mbedtls_context.peer_cert().unwrap();
            //let mut num = 0;
            let mut cert1: Option<mbedtls::alloc::Box<mbedtls::x509::Certificate>> = None;

            if let Some(certificates) = certificate_list {
                // only use first certificate returned
                for cert in certificates {
                    match cert1 {
                        None => { cert1 = Some(cert.clone()) },
                        _ => {}
                    }
                    //println!("[{}] cert: {:?}", num, cert.clone());
                    //num = num + 1;
                }
            } else {
                return Err(JoinProxyInfoError::NoCertificateFound);
            }

            // now we have the peer certificate copied into cert1.
            println!("cert1: {:?}", cert1);

            cert1
        };

        { //--------
            let mut vrq = Voucher::new_vrq();

            vrq.set(Attr::Assertion(Assertion::Proximity))
                .set(Attr::CreatedOn(1599086034))
                .set(Attr::SerialNumber(b"00-D0-E5-F2-00-02".to_vec()));

            // This is required when the `Sign` trait is backed by mbedtls v3.
            init_psa_crypto();

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
        //println!("closed");
        //Ok(())
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
