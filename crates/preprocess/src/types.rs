use ethnum::u256;

pub struct QuoteHeader {
    pub version: u16,
    pub att_key_type: u16,
    pub tee_type: u32,
    pub qe_svn: Vec<u8>,       // 2 bytes
    pub pce_svn: Vec<u8>,      // 2 bytes
    pub qe_vendor_id: Vec<u8>, // 16 bytes
    pub user_data: Vec<u8>,    // 20 bytes
}

pub struct TD10ReportBody {
    pub tee_tcb_svn: Vec<u8>,  // 16 bytes
    pub mrseam: Vec<u8>,       // 48 bytes
    pub mrsignerseam: Vec<u8>, // 48 bytes
    pub seam_attributes: u64,
    pub td_attributes: u64,
    pub xfam: u64,
    pub mrtd: Vec<u8>,          // 48 bytes
    pub mrconfigid: Vec<u8>,    // 48 bytes
    pub mrowner: Vec<u8>,       // 48 bytes
    pub mrownerconfig: Vec<u8>, // 48 bytes
    pub rtmr0: Vec<u8>,         // 48 bytes
    pub rtmr1: Vec<u8>,         // 48 bytes
    pub rtmr2: Vec<u8>,         // 48 bytes
    pub rtmr3: Vec<u8>,         // 48 bytes
    pub report_data: Vec<u8>,   // 64 bytes
}

pub struct VerifiedQuote {
    pub quote_version: u16,
    pub tee_type: u32,
    pub tcb_status: u8,
    pub fmspc: Vec<u8>, // 6 bytes
    pub quote_body: TD10ReportBody,
}

pub struct TdxModule {
    pub mrsigner: Vec<u8>, // 48 bytes
    pub attributes: u64,
    pub attributes_mask: u64,
    pub identity_id: String, // felt252 as hex string
    pub expected_id: String, // felt252 as hex string
    pub tcb_levels: Vec<TdxModuleIdentityTcbLevel>,
}

pub struct TdxModuleIdentityTcbLevel {
    pub tcb: TdxModuleTcb,
    pub tcb_status: u8,
}

pub struct TdxModuleTcb {
    pub isvsvn: u8,
}

pub struct AttestationPubKey {
    pub x: u256,
    pub y: u256,
}

/// Secp256r1 ECDSA signature.
pub struct Signature {
    pub r: u256,
    pub s: u256,
    pub y_parity: bool,
}

pub struct ContractInputs {
    pub quote_header: QuoteHeader,
    pub quote_body: TD10ReportBody,
    pub attestation_signature: Signature,
    pub attestation_pubkey: AttestationPubKey,
    pub tdx_module: TdxModule,
    pub tcb_info_svn: Vec<u8>,
}
