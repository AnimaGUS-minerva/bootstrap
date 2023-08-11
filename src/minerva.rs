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

//use crate::custom_voucher::{CustomVoucher as Voucher};
use minerva_voucher::{attr::*, SignatureAlgorithm, Sign};

use std::convert::TryFrom;

//static KEY_PEM_F2_00_02: &[u8] = core::include_bytes!(
//    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/key.pem"));
static KEY_PEM_F2_00_02: &[u8] = &[0u8]; // dummy

use std::io::{self, Cursor, Write};

pub fn brski_connect(
    connector: Arc<MbedTlsConnector>,
    agent:  Agent,
    sock:   TcpStream,
) -> Result<Request, Error> {

    //let tls_conf = &agent.config.tls_config;
    //let tls_stream = tls_conf.connect("", sock)?;

    // or can we use connect??
    let mbedtls_stream = wrap_stream_with_connector(&connector,
                                                    sock).unwrap();

    //let https_stream = Stream::new(tls_stream);
    let body = Payload::Text("Hello", "utf-8".to_string());

    let _unit = Unit::new(&agent,
                         &"POST".to_string(),
                         &Url::parse("https://localhost/.well-known/brski/requestvoucher").unwrap(),
                         vec![Header::new("User-Agent", "Minerva Bootstrap")], /* headers */
                         &body.into_read(),
                          None);
#[cfg(feature = "mbedtls")]
{ //--------
    let mbedtls_context    = mbedtls_stream.context.lock().unwrap();
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
        return Err(ErrorKind::InvalidUrl
                   .msg(format!("no certificate found")));
    }

    // now we have the peer certificate copied into cert1.
    println!("cert1: {:?}", cert1);
} //--------
    let mut vrq = Voucher::new_vrq();

    vrq.set(Attr::Assertion(Assertion::Proximity))
        .set(Attr::CreatedOn(1599086034))
        .set(Attr::SerialNumber(b"00-D0-E5-F2-00-02".to_vec()));

    // This is required when the `Sign` trait is backed by mbedtls v3.
    #[cfg(feature = "minerva-mbedtls")]
    init_psa_crypto();

    vrq.sign(KEY_PEM_F2_00_02, SignatureAlgorithm::ES256);

    let _cbor = vrq.serialize().unwrap();

    Err(ErrorKind::InvalidUrl
                .msg(format!("code incomplete")))
}

//pub fn brski_request(
//    _stream: Stream,
//) -> Result<Request, Error> {
//
//    Err(ErrorKind::InvalidUrl.msg("request incomplete"))
//}

#[cfg(feature = "minerva-mbedtls")]
pub fn init_psa_crypto() {
    use minerva_mbedtls::psa_crypto;

    psa_crypto::init().unwrap();
    psa_crypto::initialized().unwrap();
}
