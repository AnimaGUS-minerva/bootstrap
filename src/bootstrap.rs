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
use dns_lookup::{AddrInfo, AddrInfoHints, getaddrinfo, SockType};
use url::Url;
use std::collections::VecDeque;

struct JoinProxyInfo {
    url:  Url,
    addrs: Vec<AddrInfo>
}

pub struct BootstrapState {
    registrars: VecDeque<JoinProxyInfo>,
}
impl BootstrapState {
    pub fn empty() -> Self {
        BootstrapState { registrars: VecDeque::new() }
    }

    pub fn add_registrar_by_url(self: &mut Self, url: Url) {

        let hints = match url.scheme() {
            "https" => AddrInfoHints {
                socktype: SockType::Stream.into(),
                .. AddrInfoHints::default()
            },
            "coaps" => AddrInfoHints {
                socktype: SockType::DGram.into(),
                .. AddrInfoHints::default()
            },
            oscheme => { panic!("invalid scheme {}", oscheme); }
        };

        let service = format!("{}", url.port().unwrap());
        let hoststr = url.host_str().unwrap();
        let addrs   = getaddrinfo(Some(hoststr), Some(&service), Some(hints))
            .unwrap().collect::<std::io::Result<Vec<_>>>().unwrap();
        self.registrars.push_back(JoinProxyInfo {
            url:   url,
            addrs: addrs
        })
    }
}


/*
 * Local Variables:
 * mode: rust
 * compile-command: "cd .. && cargo build"
 * End:
 */
