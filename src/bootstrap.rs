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
//use dns_lookup::{AddrInfo, AddrInfoHints, lookup_host, getaddrinfo, SockType};
use std::sync::Arc;
use std::collections::VecDeque;
use std::io::{self, stdout, Write};
use std::net::SocketAddr;
use std::net::IpAddr;
use dns_lookup::{lookup_host};
use url::Url;
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::{Sender,Receiver};
use tokio::net::TcpStream;

use mbedtls::rng::OsEntropy;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::Certificate;
use mbedtls::Result as TlsResult;

#[derive(PartialEq, Debug)]
pub struct JoinProxyInfo {
    url:  Url,
    addrs: VecDeque<SocketAddr>
}

impl JoinProxyInfo {
    async fn connect_one(self: &mut Self,
                   config: Config,
                   addr:   SocketAddr,
                   entropy: Arc<OsEntropy>) -> TlsResult<()> {
        let rng       = Arc::new(CtrDrbg::new(entropy, None)?);
        //let cert    = Arc::new(Certificate::from_pem_multiple(keys::PEM_CERT.as_bytes())?);
        config.set_rng(rng);
        //config.set_ca_list(cert, None);
        let mut ctx = Context::new(Arc::new(config));

        let conn = TcpStream::connect(addr).await.unwrap();
        ctx.establish(conn, None)?;

        let line = "GET /version.json HTTP/1.0\r\n";
        ctx.write_all(line.as_bytes()).unwrap();
        io::copy(&mut ctx, &mut stdout()).unwrap();
        Ok(())
    }

    pub async fn connect(self: &mut Self) -> Result<(), std::io::Error> {
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

        let entropy = Arc::new(OsEntropy::new());

        while let Some(addr) = self.addrs.pop_front() {
            let tlserr = self.connect_one(config, addr, entropy).await;

            // examine tlserr for ECONN refused and try next IP.
            match tlserr {
                Err(x) => { return Err(std::io::Error::new(io::ErrorKind::Other, "TLS failed")) }
                Ok(x)  => { return Ok(()) }
            }
        }
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
        channel::<JoinProxyInfo>(16)
    }

    pub fn addr2sockaddr(hosts: Vec<IpAddr>, port: u16) -> VecDeque<SocketAddr> {
        VecDeque::from(hosts.map(|h| SocketAddr::new(h, port)))
    }

    pub async fn add_registrar_by_url(self: &mut Self, url: Url) -> Result<(), std::io::Error> {

        let hostname = url.host_str().unwrap();
        let port     = url.port().unwrap();
        let hosts = lookup_host(hostname)?;
        self.registrars.send(JoinProxyInfo {
            url:   url,
            addrs: BootstrapState::addr2sockaddr(hosts, port)
        }).await.unwrap();
        Ok(())
    }

    pub async fn add_registrar_by_ip(self: &mut Self, ip: std::net::IpAddr, port: u16) -> Result<(), std::io::Error> {

        let mut url = Url::from_file_path("/.well-known/brski/request/voucher").unwrap();
        url.set_ip_host(ip).unwrap();
        let hosts = vec![ip];
        self.registrars.send(JoinProxyInfo {
            url:   url,
            addrs: BootstrapState::addr2sockaddr(hosts, port)
        }).await.unwrap();
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    async fn add_registrar_url() -> Result<(), std::io::Error> {
        let url = Url::parse("https://example.com/.well-known/brski/requestvoucher").unwrap();

        let (sender, mut receiver) = BootstrapState::channel();

        let mut state = BootstrapState::empty(sender);
        state.add_registrar_by_url(url).await?;

        let thing = receiver.recv().await;
        assert_ne!(thing, None);
        Ok(())
    }
    #[test]
    fn test_add_registrar_url() {
        aw!(add_registrar_url()).unwrap();
    }

    async fn add_registrar_ip() -> Result<(), std::io::Error> {
        let (sender, mut receiver) = BootstrapState::channel();
        let mut state = BootstrapState::empty(sender);

        let ipaddr = "fe80::1234".parse().unwrap();
        state.add_registrar_by_ip(ipaddr, 8443).await?;

        let thing = receiver.recv().await;
        assert_ne!(thing, None);
        Ok(())
    }
    #[test]
    fn test_add_registrar_ip() {
        aw!(add_registrar_ip()).unwrap();
    }

    async fn add_bad_registrar_url() {
        let (sender, _receiver) = BootstrapState::channel();

        let url = Url::parse("https://foobar.example/.well-known/brski/requestvoucher").unwrap();

        let mut state = BootstrapState::empty(sender);

        let ekind = state.add_registrar_by_url(url).await.map_err(|e| e.kind());
        assert_eq!(Err(std::io::ErrorKind::Other), ekind);
    }
    #[test]
    fn test_add_bad_registrar_url() {
        aw!(add_bad_registrar_url());
    }

}



/*
 * Local Variables:
 * mode: rust
 * compile-command: "cd .. && cargo build"
 * End:
 */
