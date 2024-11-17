use crate::types::{
    QuoteHeader, QuoteHeaderImpl, TdxModule, TD10ReportBody, TD10ReportBodyImpl, ECDSASignature
};
use crate::constants::{INTEL_QE_VENDOR_ID, ECDSA_256_WITH_P256_CURVE, TDX_TEE_TYPE};
use alexandria_data_structures::span_ext::SpanTraitExt;
use alexandria_data_structures::byte_array_ext::SpanU8IntoBytearray;

use core::sha256::compute_sha256_byte_array;
use core::ecdsa::check_ecdsa_signature;

pub mod constants;
pub mod types;
pub mod common;

fn main(
    quote_header: QuoteHeader,
    quote_body: TD10ReportBody,
    attestation_signature: ECDSASignature,
    attestation_pubkey: felt252,
    tdx_module: TdxModule,
    tcb_info_svn: Span<u8>,
    min_isvsvn: u8
) -> bool {
    // Step 1: Verify quote signature
    if !verify_quote_signature(
        @quote_header, @quote_body, @attestation_signature, attestation_pubkey
    ) {
        return false;
    }

    // Step 2: Verify TDX module identity
    if !verify_tdx_module(@quote_body, @tdx_module) {
        return false;
    }

    // Step 3: Verify TCB level
    verify_tcb_level(quote_body.tee_tcb_svn.span(), tcb_info_svn, min_isvsvn)
}

fn check_quote_header(header: @QuoteHeader) -> bool {
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
    if header.qe_vendor_id.span() != INTEL_QE_VENDOR_ID.span() {
        return false;
    }

    return true;
}

fn verify_quote_signature(
    quote_header: @QuoteHeader,
    quote_body: @TD10ReportBody,
    attestation_signature: @ECDSASignature,
    attestation_pubkey: felt252,
) -> bool {
    // 1. Check header fields
    if !check_quote_header(quote_header) {
        return false;
    }

    // 2. Concatenate header and quote body data for signature verification
    let mut message = (*quote_header).to_bytes().concat((*quote_body).to_bytes());

    // 3. Hash the message with SHA256
    let message_hash = compute_sha256_byte_array(@message.span().into());

    // 4. Convert message hash bytes to felt
    let mut serialzed: Array<felt252> = ArrayTrait::new();
    message_hash.serialize(ref serialzed);
    assert(serialzed.len() == 1, 'Wrong size');
    let message_hash = *serialzed[0];

    // 5. Check ECDSA signature
    check_ecdsa_signature(
        message_hash, attestation_pubkey, *attestation_signature.r, *attestation_signature.s
    )
}

// Verify TDX module identity matches TCB info
fn verify_tdx_module(quote_body: @TD10ReportBody, tdx_module: @TdxModule) -> bool {
    // 1. Check MRSIGNER matches
    if (*quote_body.mrsignerseam).span() != (*tdx_module.mrsigner).span() {
        return false;
    }

    // 2. Check attributes with mask
    if *quote_body.seam_attributes & *tdx_module.attributes_mask != *tdx_module.attributes {
        return false;
    }

    return true;
}

// Verify TCB is at acceptable level
fn verify_tcb_level(mut tee_tcb_svn: Span<u8>, mut tcb_info_svn: Span<u8>, min_isvsvn: u8) -> bool {
    // Compare SVN values
    let mut is_valid = true;
    loop {
        match tee_tcb_svn.pop_front() {
            Option::Some(tee_tcb_svn_ele) => {
                if tee_tcb_svn_ele < tcb_info_svn.pop_front().unwrap() {
                    is_valid = false;
                    break;
                }
            },
            Option::None => { break; },
        }
    };

    is_valid
}
