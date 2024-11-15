use crate::types::quotes::QuoteHeader;
use crate::constants::{ECDSA_256_WITH_P256_CURVE, INTEL_QE_VENDOR_ID};

pub mod v4;

fn check_quote_header(quote_header: @QuoteHeader, quote_version: u16) -> bool {
    let quote_version_is_valid = *quote_header.version == quote_version;
    let att_key_type_is_supported = *quote_header.att_key_type == ECDSA_256_WITH_P256_CURVE;

    let qe_vendor_id_is_valid = quote_header.qe_vendor_id.span() == INTEL_QE_VENDOR_ID.span();

    quote_version_is_valid && att_key_type_is_supported && qe_vendor_id_is_valid
}
