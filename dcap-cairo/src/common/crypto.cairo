use starknet::SyscallResultTrait;
use crate::types::PubKey;
use core::sha256::compute_sha256_byte_array;
use alexandria_data_structures::byte_array_ext::SpanU8IntoBytearray;
use core::starknet::secp256_trait::{Signature, Secp256Trait, is_valid_signature};
use core::starknet::secp256r1::Secp256r1Point;

pub(crate) fn verify_p256_signature_bytes(
    msg: Span<u8>, signature: @Signature, pubkey: @PubKey
) -> bool {
    // Hash message to SHA-256
    let message_hash: [u32; 8] = compute_sha256_byte_array(@msg.into());

    // Convert to u256
    let message_hash_u256 = u256 {
        high: ((*message_hash.span()[0]).into() * 0x1000000000000000000000000)
            + ((*message_hash.span()[1]).into() * 0x10000000000000000)
            + ((*message_hash.span()[2]).into() * 0x100000000)
            + (*message_hash.span()[3]).into(),
        low: ((*message_hash.span()[4]).into() * 0x1000000000000000000000000)
            + ((*message_hash.span()[5]).into() * 0x10000000000000000)
            + ((*message_hash.span()[6]).into() * 0x100000000)
            + (*message_hash.span()[7]).into()
    };

    // Create public key point from x,y coordinates
    let pubkey_point =
        match Secp256Trait::<Secp256r1Point>::secp256_ec_new_syscall(*pubkey.x, *pubkey.y)
            .unwrap_syscall() {
        Option::Some(point) => point,
        Option::None => { return false; }
    };

    // Validate ECDSA signature using secp256r1
    is_valid_signature::<
        Secp256r1Point
    >(message_hash_u256, *signature.r, *signature.s, pubkey_point)
}
