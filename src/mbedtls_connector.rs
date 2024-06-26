// This requires mbedtls crate 0.11.0 or newer due to
// new Context<T> parameter
use std::fmt;
use std::io;
use ureq::{Error, ReadWrite, TlsConnector};

use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};

fn entropy_new() -> mbedtls::rng::OsEntropy {
    mbedtls::rng::OsEntropy::new()
}

pub struct MbedTlsConnector {
    pub context: Arc<Mutex<Context<Box<dyn ReadWrite>>>>,
}

#[derive(Debug)]
struct MbedTlsError;
impl fmt::Display for MbedTlsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MedTLS handshake failed")
    }
}

impl std::error::Error for MbedTlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[allow(dead_code)]
pub(crate) fn default_tls_config() -> std::sync::Arc<dyn TlsConnector> {
    Arc::new(MbedTlsConnector::new(
        mbedtls::ssl::config::AuthMode::Required,
    ))
}

impl MbedTlsConnector {
    pub fn new(mode: mbedtls::ssl::config::AuthMode) -> MbedTlsConnector {
        let entropy = Arc::new(entropy_new());
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        let rng = Arc::new(CtrDrbg::new(entropy, None).unwrap());
        config.set_rng(rng);
        config.set_authmode(mode);
        let ctx = Context::new(Arc::new(config));
        MbedTlsConnector {
            context: Arc::new(Mutex::new(ctx)),
        }
    }
}

impl TlsConnector for MbedTlsConnector {
    fn connect(
        &self,
        _dns_name: &str,
        io: Box<dyn ReadWrite>,
    ) -> Result<Box<dyn ReadWrite>, Error> {
        let mut ctx = self.context.lock().unwrap();
        match ctx.establish(io, None) {
            Err(_e) => {
                let io_err = io::Error::new(io::ErrorKind::InvalidData, MbedTlsError);
                return Err(io_err.into());
            }
            Ok(()) => Ok(MbedTlsStream::new(self)),
        }
    }
}

struct SyncIo(Mutex<Box<dyn ReadWrite>>);

impl io::Read for SyncIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut lock = self.0.lock().unwrap();
        lock.read(buf)
    }
}

impl io::Write for SyncIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut lock = self.0.lock().unwrap();
        lock.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut lock = self.0.lock().unwrap();
        lock.flush()
    }
}

struct MbedTlsStream {
    context: Arc<Mutex<Context<Box<dyn ReadWrite>>>>, //tcp_stream: TcpStream,
}

impl fmt::Debug for MbedTlsStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MbedTlsStream").finish()
    }
}

impl MbedTlsStream {
    pub fn new(mtc: &MbedTlsConnector) -> Box<MbedTlsStream> {
        Box::new(MbedTlsStream {
            context: mtc.context.clone(),
        })
    }

    //    pub fn get_peer_certificate(&self) -> Result<(), Error> {
    //        Ok(())
    //    }

}

impl ReadWrite for MbedTlsStream {
    // no obvious way to get socket back out of mbedtls context
    // context.io() returns Any, which is hard to turn back into
    // TcpStream reference, and what is lifetime of reference?
    fn socket(&self) -> Option<&TcpStream> {
        None
    }
}

impl io::Read for MbedTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut ctx = self.context.lock().unwrap();
        ctx.read(buf)
    }
}

impl io::Write for MbedTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut ctx = self.context.lock().unwrap();
        ctx.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut ctx = self.context.lock().unwrap();
        ctx.flush()
    }
}

/*
 * Local Variables:
 * compile-command: "cd ../.. && cargo build --example mbedtls-req"
 * mode: rust
 * End:
 */
