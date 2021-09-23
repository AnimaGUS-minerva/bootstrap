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
use std::path::PathBuf;
use structopt::StructOpt;
use url::Url;

#[derive(StructOpt, PartialEq, Debug)]
// Hermes Bootstrap  manager
pub struct BootstrapOptions {
    // turn on debugging from Grasp DULL
    #[structopt(default_value = "false", long, parse(try_from_str))]
    pub debug_bootstrap: bool,

    // override search and just connect to Registrar URI provided
    #[structopt(parse(try_from_str = Url::parse))]
    pub registrar: Option<Url>,

    // where to find the IDevID certificate
    #[structopt(parse(from_os_str))]
    pub idevid_cert: Option<PathBuf>,

    // where to find the IDevID private key
    #[structopt(parse(from_os_str))]
    pub idevid_priv: Option<PathBuf>,

    /// Output dir for LDevID
    #[structopt(parse(from_os_str))]
    pub ldevid_cert: Option<PathBuf>,
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_parse_args() -> Result<(), std::io::Error> {
        assert_eq!(BootstrapOptions {
            debug_bootstrap: true,
            registrar: None, idevid_cert: None, idevid_priv: None, ldevid_cert: None
        }, BootstrapOptions::from_iter(&["debug_bootstrap", "true"]));

        assert_eq!(BootstrapOptions {
            debug_bootstrap: false,
            registrar: Some(Url::parse("https://example.com/brski/rv").unwrap()),
            idevid_cert: None, idevid_priv: None, ldevid_cert: None
        }, BootstrapOptions::from_iter(&["registrar", "https://example.com/brski/rv"]));

        Ok(())
    }
}


/*
 * Local Variables:
 * mode: rust
 * compile-command: "cd .. && cargo build"
 * End:
 */
