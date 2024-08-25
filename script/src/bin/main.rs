//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use sp1_sdk::{ProverClient, SP1Stdin};
use zk_email_lib::PublicValuesStruct;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ZK_EMAIL_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long)]
    pubkey: String,

    #[clap(long)]
    signature: String,

    #[clap(long)]
    email_header: String,

    #[clap(long)]
    max_headers_length: u32,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.pubkey);
    stdin.write(&args.signature);
    stdin.write(&args.email_header);
    stdin.write(&args.max_headers_length);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(ZK_EMAIL_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        let PublicValuesStruct {
            pubkey,
            signature,
            email_header,
            pubkey_hash,
            max_headers_length,
        } = decoded;

        println!("pubkey: {}", pubkey);
        println!("signature: {}", signature);
        println!("email_header: {}", email_header);
        println!("pubkey_hash: {}", pubkey_hash);
        println!("max_headers_length: {}", max_headers_length);

        let expected_pubkey_hash = zk_email_lib::verify_dkim_signature(
            &pubkey.to_vec(),
            &signature.to_vec(),
            &email_header.to_vec(),
            max_headers_length,
        );
        assert_eq!(pubkey_hash, expected_pubkey_hash);
        println!("Values are correct!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(ZK_EMAIL_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
