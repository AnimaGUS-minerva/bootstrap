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
use std::path::PathBuf;
use clap::{Parser};
use url::Url;
use ring::{allkeys::GenericKeyPair};
use x509_cert::Certificate;
//use rustls_pki_types::{PrivatePkcs8KeyDer};
use crate::error::BsError;
use der::{
    Decode
};

#[derive(Parser, PartialEq, Debug, Clone)]
#[command(name="bootstrap")]
#[command(version = "1.0")]
#[command(about = "Hermes Connect Pledge BRSKI client", long_about = None)]
/// Hermes Bootstrap manager
pub struct BootstrapOptions {
    /// turn on debugging of processing
    #[arg(long,num_args(0..=1))]
    pub debug_bootstrap: bool,

    /// override search and just connect to Registrar URI provided
    #[arg(long)]
    pub registrar: Option<Url>,

    /// where to find the IDevID certificate
    #[arg(long)]
    pub idevid_cert: Option<PathBuf>,

    /// where to find the IDevID private key
    #[arg(long)]
    pub idevid_priv: Option<PathBuf>,

    /// output file for LDevID after enrollment
    #[arg(long)]
    pub ldevid_cert: Option<PathBuf>,
}

#[cfg(test)]
pub mod tests {
    use super::*;

    // argument parse ignores first argument, which would be argv[0]
    #[test]
    fn test_parse_args() -> Result<(), std::io::Error> {
        assert_eq!(BootstrapOptions {
            debug_bootstrap: true,
            registrar: None, idevid_cert: None, idevid_priv: None, ldevid_cert: None
        }, BootstrapOptions::parse_from(["bootstrap", "--debug-bootstrap=true"]));

        Ok(())
    }

    #[test]
    fn test_parse_args_ldevid() -> Result<(), std::io::Error> {
        let args = BootstrapOptions::parse_from(["bootstrap", "--ldevid-cert=testdata/00-D0-E5-F2-00-01/device.crt"]);

        assert_eq!(BootstrapOptions {
            debug_bootstrap: false,
            registrar: None,
            idevid_cert: None,
            idevid_priv: None,
            ldevid_cert: Some("testdata/00-D0-E5-F2-00-01/device.crt".into())
        }, args);

        assert!(args.pledge_details().unwrap().is_some(),
                "Failed to read device.crt (did you submodule init?)");
        Ok(())
    }

    #[test]
    fn test_parse_args_registrar() -> Result<(), std::io::Error> {
        assert_eq!(BootstrapOptions {
            debug_bootstrap: false,
            registrar: Some(Url::parse("https://example.com/brski/rv").unwrap()),
            idevid_cert: None, idevid_priv: None, ldevid_cert: None
        }, BootstrapOptions::parse_from(["bootstrap",
                                         "--registrar=https://example.com/brski/rv"]));

        Ok(())
    }
    #[test]
    fn test_parse_args_registrar_with_port() -> Result<(), std::io::Error> {
        assert_eq!(BootstrapOptions {
            debug_bootstrap: false,
            registrar: Some(Url::parse("https://example.com:8443/brski/rv").unwrap()),
            idevid_cert: None, idevid_priv: None, ldevid_cert: None
        }, BootstrapOptions::parse_from(["bootstrap",
                                         "--registrar=https://example.com:8443/brski/rv"]));

        Ok(())
    }

    // this one fails, because an entire URL is required
    #[allow(dead_code)]
    fn test_parse_args_registrar_hostname() -> Result<(), std::io::Error> {
        assert_eq!(BootstrapOptions {
            debug_bootstrap: false,
            registrar: Some(Url::parse("https://example.com/").unwrap()),
            idevid_cert: None, idevid_priv: None, ldevid_cert: None
        }, BootstrapOptions::parse_from(["bootstrap",
                                         "--registrar=example.com"]));

        Ok(())
    }
}


/*
 * Local Variables:
 * mode: rust
 * compile-command: "cd .. && cargo build"
 * End:
 */
