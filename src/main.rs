use std::sync::Arc;
use tokio::runtime;
use structopt::StructOpt;

static VERSION: &str = "0.9.0";

#[derive(StructOpt)]
// Hermes Connect Autonomic Control Plane (ACP) manager
struct ConnectOptions {
    // turn on debugging from Grasp DULL
    #[structopt(default_value = "false", long, parse(try_from_str))]
    debug_bootstrap: bool,
}

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
