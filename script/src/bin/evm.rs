//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use serde::{Deserialize, Serialize};
use sp1_sdk::{HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};
use std::path::PathBuf;
use zk_email_lib::PublicValuesStruct;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ZK_EMAIL_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the EVM command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct EVMArgs {
    #[clap(long, default_value = "20")]
    n: u32,
}

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1ZkEmailProofFixture {
    pubkey: Vec<u8>,
    signature: Vec<u8>,
    email_header: Vec<u8>,
    pubkey_hash: bool,
    max_headers_length: u32,
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = EVMArgs::parse();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(ZK_EMAIL_ELF);

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.n);

    println!("n: {}", args.n);

    // Generate the proof.
    let proof = client
        .prove(&pk, stdin)
        .plonk()
        .run()
        .expect("failed to generate proof");

    create_plonk_fixture(&proof, &vk);
}

/// Create a fixture for the given proof.
fn create_plonk_fixture(proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey) {
    // Deserialize the public values.
    let bytes = proof.public_values.as_slice();
    let PublicValuesStruct {
        pubkey,
        signature,
        email_header,
        pubkey_hash,
        max_headers_length,
    } = PublicValuesStruct::abi_decode(bytes, false).unwrap();

    // Create the testing fixture so we can test things end-to-end.
    let fixture = SP1ZkEmailProofFixture {
        pubkey: pubkey.to_vec(),
        signature: signature.to_vec(),
        email_header: email_header.to_vec(),
        pubkey_hash,
        max_headers_length,
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    // The verification key is used to verify that the proof corresponds to the execution of the
    // program on the given input.
    //
    // Note that the verification key stays the same regardless of the input.
    println!("Verification Key: {}", fixture.vkey);

    // The public values are the values which are publicly committed to by the zkVM.
    //
    // If you need to expose the inputs or outputs of your program, you should commit them in
    // the public values.
    println!("Public Values: {}", fixture.public_values);

    // The proof proves to the verifier that the program was executed with some inputs that led to
    // the give public values.
    println!("Proof Bytes: {}", fixture.proof);

    // Save the fixture to a file.
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join("fixture.json"),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}
