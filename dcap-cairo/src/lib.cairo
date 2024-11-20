use starknet::SyscallResultTrait;
use crate::types::{
    QuoteHeader, QuoteHeaderImpl, TdxModule, TD10ReportBody, TD10ReportBodyImpl, AttestationPubKey
};
use crate::constants::{INTEL_QE_VENDOR_ID, ECDSA_256_WITH_P256_CURVE, TDX_TEE_TYPE};
use alexandria_data_structures::span_ext::SpanTraitExt;
use alexandria_data_structures::byte_array_ext::SpanU8IntoBytearray;
use core::sha256::compute_sha256_byte_array;
use core::starknet::secp256_trait::{Signature, Secp256Trait, is_valid_signature};
use core::starknet::secp256r1::Secp256r1Point;

pub mod constants;
pub mod types;
pub mod common;

pub fn check_quote_header(header: @QuoteHeader) -> bool {
    // Version check
    if *header.version != 4 {
        return false;
    }

    // Key type check
    if *header.att_key_type != ECDSA_256_WITH_P256_CURVE {
        return false;
    }

    // TEE type check
    if *header.tee_type != TDX_TEE_TYPE {
        return false;
    }

    // Vendor ID check
    if *header.qe_vendor_id != INTEL_QE_VENDOR_ID.span() {
        return false;
    }

    return true;
}

pub fn verify_quote_signature(
    quote_header: @QuoteHeader,
    quote_body: @TD10ReportBody,
    attestation_signature: @Signature,
    attestation_pubkey: AttestationPubKey,
) -> bool {
    // Check header fields
    if !check_quote_header(quote_header) {
        return false;
    }

    // Concatenate header and quote body data for signature verification
    let mut message = (*quote_header).to_bytes().concat((*quote_body).to_bytes());

    // Hash message to SHA-256
    let message_hash: [u32; 8] = compute_sha256_byte_array(@message.span().into());

    // Convert message hash array to u256
    let message_hash_u256 = u256 {
        low: ((*message_hash.span()[0]).into() * 0x100000000_u128
            + (*message_hash.span()[1]).into())
            + ((*message_hash.span()[2]).into() * 0x100000000_u128
                + (*message_hash.span()[3]).into())
                * 0x100000000_u128,
        high: ((*message_hash.span()[4]).into() * 0x100000000_u128
            + (*message_hash.span()[5]).into())
            + ((*message_hash.span()[6]).into() * 0x100000000_u128
                + (*message_hash.span()[7]).into())
                * 0x100000000_u128,
    };

    // Create public key point from x,y coordinates
    let pubkey_point =
        match Secp256Trait::<
            Secp256r1Point
        >::secp256_ec_new_syscall(attestation_pubkey.x, attestation_pubkey.y)
            .unwrap_syscall() {
        Option::Some(point) => point,
        Option::None => { return false; }
    };

    // Validate ECDSA signature using secp256r1
    is_valid_signature::<
        Secp256r1Point
    >(message_hash_u256, *attestation_signature.r, *attestation_signature.s, pubkey_point)
}

// Verify TDX module identity matches TCB info
pub fn verify_tdx_module(quote_body: @TD10ReportBody, tdx_module: @TdxModule) -> bool {
    // Check MRSIGNER matches
    if (*quote_body.mrsignerseam) != (*tdx_module.mrsigner) {
        return false;
    }

    // Check attributes with mask
    if *quote_body.seam_attributes & *tdx_module.attributes_mask != *tdx_module.attributes {
        return false;
    }

    return true;
}

// Verify TCB level
pub fn verify_tdx_tcb(tee_tcb_svn: Span<u8>, tdx_module: @TdxModule) -> u8 {
    // Get ISV SVN and version from TEE TCB SVN
    let tdx_module_isv_svn = *tee_tcb_svn[0];
    let tdx_module_version = *tee_tcb_svn[1];

    // Special case for version 0
    if tdx_module_version == 0 {
        return 0;
    }

    // Verify module ID matches
    if *tdx_module.identity_id != *tdx_module.expected_id {
        return 7;
    }

    // Find highest TCB level where our ISV SVN meets minimum
    let mut tcb_status = 7;
    let mut tcb_levels = *tdx_module.tcb_levels;
    loop {
        match tcb_levels.pop_front() {
            Option::Some(level) => {
                if tdx_module_isv_svn >= *level.tcb.isvsvn {
                    tcb_status = *level.tcb_status;
                    break;
                }
            },
            Option::None => { break; },
        }
    };

    tcb_status
}
