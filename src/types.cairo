use crate::common::bytes::{U16BytesImpl, U32BytesImpl, U64BytesImpl};

#[derive(Copy, Drop, Serde)]
pub struct QuoteHeader {
    pub version: u16,
    pub att_key_type: u16,
    pub tee_type: u32,
    pub qe_svn: Span<u8>, // 2 bytes
    pub pce_svn: Span<u8>, // 2 bytes
    pub qe_vendor_id: Span<u8>, // 16 bytes
    pub user_data: Span<u8> // 20 bytes
}

#[generate_trait]
pub impl QuoteHeaderImpl of QuoteHeaderTrait {
    fn to_bytes(mut self: QuoteHeader) -> Span<u8> {
        let mut raw_bytes = ArrayTrait::new();

        raw_bytes.append_span(U16BytesImpl::to_le_bytes(self.version));
        raw_bytes.append_span(U16BytesImpl::to_le_bytes(self.att_key_type));
        raw_bytes.append_span(U32BytesImpl::to_le_bytes(self.tee_type));
        raw_bytes.append_span(self.qe_svn);
        raw_bytes.append_span(self.pce_svn);
        raw_bytes.append_span(self.qe_vendor_id);
        raw_bytes.append_span(self.user_data);

        raw_bytes.span()
    }
}

#[derive(Copy, Drop, Serde)]
pub struct TD10ReportBody {
    pub tee_tcb_svn: Span<u8>, // 16 bytes
    pub mrseam: Span<u8>, // 48 bytes
    pub mrsignerseam: Span<u8>, // 48 bytes
    pub seam_attributes: u64,
    pub td_attributes: u64,
    pub xfam: u64,
    pub mrtd: Span<u8>, // 48 bytes
    pub mrconfigid: Span<u8>, // 48 bytes
    pub mrowner: Span<u8>, // 48 bytes
    pub mrownerconfig: Span<u8>, // 48 bytes
    pub rtmr0: Span<u8>, // 48 bytes
    pub rtmr1: Span<u8>, // 48 bytes
    pub rtmr2: Span<u8>, // 48 bytes
    pub rtmr3: Span<u8>, // 48 bytes
    pub report_data: Span<u8>, // 64 bytes
}

#[generate_trait]
pub impl TD10ReportBodyImpl of TD10ReportBodyTrait {
    fn to_bytes(mut self: TD10ReportBody) -> Span<u8> {
        let mut raw_bytes = ArrayTrait::new();

        raw_bytes.append_span(self.tee_tcb_svn);
        raw_bytes.append_span(self.mrseam);
        raw_bytes.append_span(self.mrsignerseam);
        raw_bytes.append_span(U64BytesImpl::to_le_bytes(self.seam_attributes));
        raw_bytes.append_span(U64BytesImpl::to_le_bytes(self.td_attributes));
        raw_bytes.append_span(U64BytesImpl::to_le_bytes(self.xfam));
        raw_bytes.append_span(self.mrtd);
        raw_bytes.append_span(self.mrconfigid);
        raw_bytes.append_span(self.mrowner);
        raw_bytes.append_span(self.mrownerconfig);
        raw_bytes.append_span(self.rtmr0);
        raw_bytes.append_span(self.rtmr1);
        raw_bytes.append_span(self.rtmr2);
        raw_bytes.append_span(self.rtmr3);
        raw_bytes.append_span(self.report_data);

        raw_bytes.span()
    }
}


#[derive(Copy, Drop, Serde)]
pub struct VerifiedQuote {
    pub quote_version: u16,
    pub tee_type: u32,
    pub tcb_status: u8,
    pub fmspc: Span<u8>, // 6 bytes
    pub quote_body: TD10ReportBody
}

#[derive(Copy, Drop, Serde)]
pub struct ECDSASignature {
    pub r: felt252,
    pub s: felt252
}

// TDX Module Fields parsed from TCBInfo
#[derive(Drop, Serde)]
pub struct TdxModule {
    pub mrsigner: Span<u8>, // 48 bytes
    pub attributes: u64,
    pub attributes_mask: u64,
    pub identity_id: felt252,
    pub expected_id: felt252,
    pub tcb_levels: Span<TdxModuleIdentityTcbLevel>
}

#[derive(Drop, Copy, Serde)]
pub struct TdxModuleIdentityTcbLevel {
    pub tcb: TdxModuleTcb,
    pub tcb_status: u8,
}

#[derive(Drop, Copy, Serde)]
pub struct TdxModuleTcb {
    pub isvsvn: u8
}

const TCB_STATUS_OK: u8 = 0;
const TCB_STATUS_SW_HARDENING_NEEDED: u8 = 1;
const TCB_STATUS_CONFIG_NEEDED: u8 = 2;
const TCB_STATUS_CONFIG_AND_SW_HARDENING_NEEDED: u8 = 3;
const TCB_STATUS_OUT_OF_DATE: u8 = 4;
const TCB_STATUS_OUT_OF_DATE_CONFIG_NEEDED: u8 = 5;
const TCB_STATUS_REVOKED: u8 = 6;
const TCB_STATUS_UNRECOGNIZED: u8 = 7;
