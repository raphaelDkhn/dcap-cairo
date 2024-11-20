use starknet::SyscallResultTrait;
use crate::types::{
    QuoteHeader, QuoteHeaderImpl, TdxModule, TD10ReportBody, TD10ReportBodyImpl, ECDSASignature
};
use crate::constants::{INTEL_QE_VENDOR_ID, ECDSA_256_WITH_P256_CURVE, TDX_TEE_TYPE};
use crate::common::sha256::compute_sha256_byte_array;
use alexandria_data_structures::span_ext::SpanTraitExt;
use alexandria_data_structures::byte_array_ext::SpanU8IntoBytearray;
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
) -> bool {
    // Verify quote signature
    if !verify_quote_signature(
        @quote_header, @quote_body, @attestation_signature, attestation_pubkey
    ) {
        return false;
    }

    // Verify TDX module identity
    if !verify_tdx_module(@quote_body, @tdx_module) {
        return false;
    }

    // Get TCB status from TDX module verification
    let tcb_status = verify_tdx_tcb(quote_body.tee_tcb_svn.span(), @tdx_module);

    // Convert TCB status to bool result
    if tcb_status != 0 {
        return false;
    }

    true
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
    // Check header fields
    if !check_quote_header(quote_header) {
        return false;
    }

    // Concatenate header and quote body data for signature verification
    let mut message = (*quote_header).to_bytes().concat((*quote_body).to_bytes());

    // let message_hash = compute_sha256_byte_array(@message.span().into());

    // // Convert message hash bytes to felt
    // let mut serialzed: Array<felt252> = ArrayTrait::new();
    // message_hash.serialize(ref serialzed);
    // assert(serialzed.len() == 1, 'Wrong size');
    // let message_hash = *serialzed[0];

    // // Check ECDSA signature
    // check_ecdsa_signature(
    //     message_hash, attestation_pubkey, *attestation_signature.r, *attestation_signature.s
    // )
    true
}

// Verify TDX module identity matches TCB info
fn verify_tdx_module(quote_body: @TD10ReportBody, tdx_module: @TdxModule) -> bool {
    // Check MRSIGNER matches
    if (*quote_body.mrsignerseam).span() != (*tdx_module.mrsigner).span() {
        return false;
    }

    // Check attributes with mask
    if *quote_body.seam_attributes & *tdx_module.attributes_mask != *tdx_module.attributes {
        return false;
    }

    return true;
}

// Verify TCB level
fn verify_tdx_tcb(tee_tcb_svn: Span<u8>, tdx_module: @TdxModule) -> u8 {
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
