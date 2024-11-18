use serde::{Deserialize, Serialize};

// Structures that match Cairo's expected input format
#[derive(Serialize, Deserialize, Debug)]
pub struct CairoQuoteHeader {
    pub version: u16,
    pub att_key_type: u16,
    pub tee_type: u32,
    pub qe_svn: Vec<u8>,
    pub pce_svn: Vec<u8>,
    pub qe_vendor_id: Vec<u8>,
    pub user_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CairoTD10Report {
    pub tee_tcb_svn: Vec<u8>,
    pub mrseam: Vec<u8>,
    pub mrsignerseam: Vec<u8>,
    pub seam_attributes: u64,
    pub td_attributes: u64,
    pub xfam: u64,
    pub mrtd: Vec<u8>,
    pub mrconfigid: Vec<u8>,
    pub mrowner: Vec<u8>,
    pub mrownerconfig: Vec<u8>,
    pub rtmr0: Vec<u8>,
    pub rtmr1: Vec<u8>,
    pub rtmr2: Vec<u8>,
    pub rtmr3: Vec<u8>,
    pub report_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CairoTDXModule {
    pub mrsigner: Vec<u8>,
    pub attributes: u64,
    pub attributes_mask: u64,
    pub identity_id: String, // felt252 as hex string
    pub expected_id: String, // felt252 as hex string
    pub tcb_levels: Vec<CairoTdxModuleTcbLevel>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CairoTdxModuleTcbLevel {
    pub tcb: CairoTdxModuleTcb,
    pub tcb_status: u8,   // Enum value
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CairoTdxModuleTcb {
    pub isvsvn: u8,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CairoECDSASignature {
    pub r: String, // felt252 as hex string
    pub s: String, // felt252 as hex string
}

#[derive(Debug)]
pub struct CairoVerificationInputs {
    pub quote_header: CairoQuoteHeader,
    pub quote_body: CairoTD10Report,
    pub attestation_signature: CairoECDSASignature,
    pub attestation_pubkey: String, // felt252 as hex string
    pub tdx_module: CairoTDXModule,
    pub tcb_info_svn: Vec<u8>,
}
