use std::sync::Arc;
use std::path::PathBuf;
use tokio::runtime;
use structopt::StructOpt;
use url::Url;

static VERSION: &str = "0.9.0";
static DEFAULT_JOIN_THREADS: u16 = 16;

#[derive(StructOpt)]
// Hermes Connect Autonomic Control Plane (ACP) manager
struct ConnectOptions {
    // turn on debugging from Grasp DULL
    #[structopt(default_value = "false", long, parse(try_from_str))]
    debug_bootstrap: bool,

    // override search and just connect to Registrar URI provided
    #[structopt(parse(try_from_str = Url::parse))]
    registrar: Option<Url>,

    // where to find the IDevID certificate
    #[structopt(parse(from_os_str))]
    idevid_cert: Option<PathBuf>,

    // where to find the IDevID private key
    #[structopt(parse(from_os_str))]
    idevid_priv: Option<PathBuf>,

    /// Output dir for LDevID
    #[structopt(parse(from_os_str))]
    ldevid_cert: Option<PathBuf>,
}

/*
 * Bootstrap is a program in a few distinct states.
 *
 * 1. It has no IDevID provisioned as yet. It waits for one to show up,
 *    so that it can move to state 2.
 *
 * 2. It has an IDevID private key and certificate, so it looks for
 *    candidate Join Proxy on each of it's physical interfaces.
 *
 * 3. For each physical interface found, a thread is created to start an mbedtls
 *    connection to the join proxy, to start onboarding via BRSKI (RFC8995).
 *    A maximum of ConnectionOptions.join_threads is allowed to run.
 *    Any additional ones are put in a queue.
 *
 * 4. If a thread takes too long, or fails, then the interface is put back on
 *    the queue to be dealt with soon.
 *
*/


async fn bootstrap(_args: ConnectOptions) -> Result<(), String> {
    println!("Hello");

    Ok(())
}

fn main () -> Result<(), String> {

    println!("Hermes Bootstrap {}", VERSION);

    let args = ConnectOptions::from_args();

    // tokio 1.7
    let brt = runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("parent")
        .enable_all()
        .build()
        .unwrap();

    let rt = Arc::new(brt);
    let future = bootstrap(args);
    // This will run the runtime and future on the current thread
    rt.block_on(async { future.await.unwrap(); } );

    return Ok(());
}



/*
 * Local Variables:
 * mode: rust
 * compile-command: "cd .. && cargo build"
 * End:
 */
