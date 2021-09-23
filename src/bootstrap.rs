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
use dns_lookup::{lookup_host};
use url::Url;
use std::collections::VecDeque;

struct JoinProxyInfo {
    url:  Url,
    addrs: Vec<std::net::IpAddr>
}

pub struct BootstrapState {
    registrars: VecDeque<JoinProxyInfo>,
}
impl BootstrapState {
    pub fn empty() -> Self {
        BootstrapState { registrars: VecDeque::new() }
    }

    pub fn add_registrar_by_url(self: &mut Self, url: Url) -> Result<(), std::io::Error> {

        let hostname = url.host_str().unwrap();
        let hosts = lookup_host(hostname)?;
        self.registrars.push_back(JoinProxyInfo {
            url:   url,
            addrs: hosts
        });
        Ok(())

    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_add_registrar_url() -> Result<(), std::io::Error> {
        let url = Url::parse("https://example.com/.well-known/brski/requestvoucher").unwrap();

        let mut state = BootstrapState::empty();
        state.add_registrar_by_url(url)?;

        assert_eq!(state.registrars.len(), 1);
        Ok(())
     }

    #[test]
    fn test_add_bad_registrar_url() {
        let url = Url::parse("https://foobar.example/.well-known/brski/requestvoucher").unwrap();

        let mut state = BootstrapState::empty();

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
