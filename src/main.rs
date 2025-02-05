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
//use std::sync::Arc;
use structopt::StructOpt;
//use psa_crypto;

pub mod args;
pub mod bootstrap;
pub mod mbedtls_connector;
mod support_rand;
mod custom_voucher;
mod utils;
use bootstrap::BootstrapState;

static VERSION: &str = "0.9.0";
//static DEFAULT_JOIN_THREADS: u16 = 16;

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

fn bootstrap(args: args::BootstrapOptions) -> Result<(), String> {
    let (sender, receiver) = BootstrapState::channel();
    let mut state = BootstrapState::empty(sender);

    //init_psa_crypto();

    if let Some(url) = args.registrar {
        state.add_registrar_by_url(url.clone()).unwrap();
    } else {
        // start loop looking for interfaces,
        // and within that loop, listen for GRASP announcements
    }

    // now make loop that looks for new Registrars to process.
    // when Bootstrap.registrar is empty, then wait for signal
    //rt.spawn(async move {   // receiver moved
    println!("Looking for Registrars using GRASP");
    while let Ok(mut reg) = receiver.recv() {
        reg.connect().unwrap();
    }

        // we get here because sender got dropped
    //});

    //


    Ok(())
}

fn main () -> Result<(), String> {

    println!("Hermes Bootstrap {}", VERSION);

    let args = args::BootstrapOptions::from_args();
    println!("Options {:?}", args);

    bootstrap(args).unwrap();
    return Ok(());
}



/*
 * Local Variables:
 * mode: rust
 * compile-command: "cd .. && cargo build"
 * End:
 */
