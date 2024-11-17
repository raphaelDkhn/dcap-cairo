use crate::common::{U16BytesImpl, U32BytesImpl, U64BytesImpl};

#[derive(Copy, Drop)]
pub struct QuoteHeader {
    pub version: u16,
    pub att_key_type: u16, 
    pub tee_type: u32,
    pub qe_svn: [u8; 2],
    pub pce_svn: [u8; 2],
    pub qe_vendor_id: [u8; 16], 
    pub user_data: [u8; 20] 
}

#[generate_trait]
pub impl QuoteHeaderImpl of QuoteHeaderTrait {
    fn to_bytes(mut self: QuoteHeader) -> Span<u8> {
        let mut raw_bytes = ArrayTrait::new();

        raw_bytes.append_span(U16BytesImpl::to_le_bytes(self.version));
        raw_bytes.append_span(U16BytesImpl::to_le_bytes(self.att_key_type));
        raw_bytes.append_span(U32BytesImpl::to_le_bytes(self.tee_type));
        raw_bytes.append_span(self.qe_svn.span());
        raw_bytes.append_span(self.pce_svn.span());
        raw_bytes.append_span(self.qe_vendor_id.span());
        raw_bytes.append_span(self.user_data.span());

        raw_bytes.span()
    }
}

#[derive(Copy, Drop)]
pub struct TD10ReportBody {
    pub tee_tcb_svn: [u8; 16],
    pub mrseam: [u8; 48], 
    pub mrsignerseam: [u8; 48],
    pub seam_attributes: u64,
    pub td_attributes: u64,
    pub xfam: u64,
    pub mrtd: [u8; 48],
    pub mrconfigid: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
    pub report_data: [u8; 64]
}

#[generate_trait]
pub impl TD10ReportBodyImpl of TD10ReportBodyTrait {
    fn to_bytes(mut self: TD10ReportBody) -> Span<u8> {
        let mut raw_bytes = ArrayTrait::new();

        raw_bytes.append_span(self.tee_tcb_svn.span());
        raw_bytes.append_span(self.mrseam.span());
        raw_bytes.append_span(self.mrsignerseam.span());
        raw_bytes.append_span(U64BytesImpl::to_le_bytes(self.seam_attributes));
        raw_bytes.append_span(U64BytesImpl::to_le_bytes(self.td_attributes));
        raw_bytes.append_span(U64BytesImpl::to_le_bytes(self.xfam));
        raw_bytes.append_span(self.mrtd.span());
        raw_bytes.append_span(self.mrconfigid.span());
        raw_bytes.append_span(self.mrowner.span());
        raw_bytes.append_span(self.mrownerconfig.span());
        raw_bytes.append_span(self.rtmr0.span());
        raw_bytes.append_span(self.rtmr1.span());
        raw_bytes.append_span(self.rtmr2.span());
        raw_bytes.append_span(self.rtmr3.span());
        raw_bytes.append_span(self.report_data.span());

        raw_bytes.span()
    }
}


#[derive(Copy, Drop)]
pub struct VerifiedQuote {
    pub quote_version: u16,
    pub tee_type: u32,
    pub tcb_status: u8,
    pub fmspc: [u8; 6],
    pub quote_body: TD10ReportBody
}

#[derive(Copy, Drop)]
pub struct ECDSASignature {
   pub r: felt252,
   pub s: felt252
}

// TDX Module Fields parsed from TCBInfo
#[derive(Drop)]  
pub struct TdxModule {
    pub mrsigner: [u8; 48], // 48 bytes
    pub attributes: u64,
    pub attributes_mask: u64
}

enum TcbStatus {
    TCB_STATUS_OK,
    TCB_STATUS_SW_HARDENING_NEEDED,
    TCB_STATUS_CONFIG_AND_SW_HARDENING_NEEDED,
    TCB_STATUS_CONFIG_NEEDED,
    TCB_STATUS_OUT_OF_DATE,
    TCB_STATUS_OUT_OF_DATE_CONFIG_NEEDED,
    TCB_STATUS_REVOKED,
    TCB_STATUS_UNRECOGNIZED
}