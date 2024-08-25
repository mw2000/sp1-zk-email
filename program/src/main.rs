#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::{private::FixedBytes, SolType};
use zk_email_lib::{verify_dkim_signature, PublicValuesStruct};

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let pubkey = sp1_zkvm::io::read::<Vec<u8>>();
    let signature = sp1_zkvm::io::read::<Vec<u8>>();
    let email_header = sp1_zkvm::io::read::<Vec<u8>>();
    let max_headers_length = sp1_zkvm::io::read::<u32>();

    // Compute the n'th fibonacci number using a function from the workspace lib crate.
    let pubkey_hash = verify_dkim_signature(&pubkey, &signature, &email_header, max_headers_length);

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        pubkey: FixedBytes::from_slice(pubkey.as_slice()),
        signature: FixedBytes::from_slice(signature.as_slice()),
        email_header: FixedBytes::from_slice(email_header.as_slice()),
        pubkey_hash,
        max_headers_length: u32::from_be_bytes(max_headers_length.to_be_bytes()),
    });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
