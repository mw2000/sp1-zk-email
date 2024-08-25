use alloy_sol_types::sol;
use p3_poseidon2::Poseidon2;
use rsa::{pkcs8::DecodePublicKey, PaddingScheme::PKCS1v15Encrypt, PublicKey, RsaPublicKey};
use sha2::{Digest, Sha256};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bytes32 pubkey;
        bytes32 signature;
        bool pubkey_hash;
        bytes32 email_header;
        uint32 max_headers_length;
    }
}

pub fn verify_dkim_signature(
    pubkey: &Vec<u8>,
    signature: &Vec<u8>,
    email_header: &Vec<u8>,
    max_headers_length: u32,
) -> bool {
    // assert!(signature.len() == 8);
    // assert!(email_header.len() < max_headers_length as usize / 8);
    // Decode the base64-encoded signature

    if (signature.len() != 8) || (email_header.len() > max_headers_length as usize / 8) {
        return false;
    }

    let decoded_signature = signature.as_slice();

    // Hash the email header using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&email_header[..max_headers_length as usize]);
    let email_header_hash = hasher.finalize();

    // Create an RSA public key from the provided public key bytes
    let rsa_pubkey = match RsaPublicKey::from_public_key_der(&pubkey) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // Verify the RSA signature
    let verification = rsa_pubkey.verify(
        PKCS1v15Encrypt,
        email_header_hash.as_slice(),
        decoded_signature,
    );

    // assert!(verification.is_ok());
    verification.is_ok()

    // Need to potentially generate poseidon hash for the pubkey
    // We might not need it though based on comments in the original code
    // since we can generate a plonk proof here from the verification itself
}
