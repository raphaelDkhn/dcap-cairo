use crate::common::bytes::{U16BytesImpl, U64BytesImpl};

pub enum QuoteBody {
    SGXQuoteBody: EnclaveReport,
    TD10QuoteBody: TD10ReportBody
}

#[derive(Drop)]
pub struct EnclaveReport {
    // [16 bytes]
    // Security Version of the CPU (raw value)
    pub cpu_svn: Span<u8>,
    // [4 bytes]
    // SSA Frame extended feature set.
    // Reports what SECS.MISCSELECT settings are used in the enclave. You can limit the
    // allowed MISCSELECT settings in the sigstruct using MISCSELECT/MISCMASK.
    pub misc_select: Span<u8>,
    // [28 bytes]
    // Reserved for future use - 0
    pub reserved_1: Span<u8>,
    // [16 bytes]
    // Set of flags describing attributes of the enclave.
    // Reports what SECS.ATTRIBUTES settings are used in the enclave. The ISV can limit what
    // SECS.ATTRIBUTES can be used when loading the enclave through parameters to the SGX Signtool.
    // The Signtool will produce a SIGSTRUCT with ATTRIBUTES and ATTRIBUTESMASK
    // which determine allowed ATTRIBUTES.
    // - For each SIGSTRUCT.ATTRIBUTESMASK bit that is set, then corresponding bit in the
    // SECS.ATTRIBUTES must match the same bit in SIGSTRUCT.ATTRIBUTES.
    pub attributes: Span<u8>,
    // [32 bytes]
    // Measurement of the enclave.
    // The MRENCLAVE value is the SHA256 hash of the ENCLAVEHASH field in the SIGSTRUCT.
    pub mrenclave: Span<u8>,
    // [32 bytes]
    // Reserved for future use - 0
    pub reserved_2: Span<u8>,
    // [32 bytes]
    // Measurement of the enclave signer.
    // The MRSIGNER value is the SHA256 hash of the MODULUS field in the SIGSTRUCT.
    pub mrsigner: Span<u8>,
    // [96 bytes]
    // Reserved for future use - 0
    pub reserved_3: Span<u8>,
    // [2 bytes]
    // Product ID of the enclave.
    // The ISV should configure a unique ISVProdID for each product which may
    // want to share sealed data between enclaves signed with a specific MRSIGNER. The ISV
    // may want to supply different data to identical enclaves signed for different products.
    pub isv_prod_id: u16,
    // [2 bytes]
    // Security Version of the enclave
    pub isv_svn: u16,
    // [60 bytes]
    // Reserved for future use - 0
    pub reserved_4: Span<u8>,
    // [64 bytes]
    // Additional report data.
    // The enclave is free to provide 64 bytes of custom data to the REPORT.
    // This can be used to provide specific data from the enclave or it can be used to hold
    // a hash of a larger block of data which is provided with the quote.
    // The verification of the quote signature confirms the integrity of the
    // report data (and the rest of the REPORT body).
    pub report_data: Span<u8>
}

#[generate_trait]
pub impl EnclaveReportImpl of EnclaveReportTrait {
    fn from_bytes(mut raw_bytes: Span<u8>) -> EnclaveReport {
        assert(raw_bytes.len() == 384, 'Wrong size');

        EnclaveReport {
            cpu_svn: (*(raw_bytes.multi_pop_front::<16>().unwrap())).unbox().span(),
            misc_select: (*(raw_bytes.multi_pop_front::<4>().unwrap())).unbox().span(),
            reserved_1: (*(raw_bytes.multi_pop_front::<28>().unwrap())).unbox().span(),
            attributes: (*(raw_bytes.multi_pop_front::<16>().unwrap())).unbox().span(),
            mrenclave: (*(raw_bytes.multi_pop_front::<32>().unwrap())).unbox().span(),
            reserved_2: (*(raw_bytes.multi_pop_front::<32>().unwrap())).unbox().span(),
            mrsigner: (*(raw_bytes.multi_pop_front::<32>().unwrap())).unbox().span(),
            reserved_3: (*(raw_bytes.multi_pop_front::<96>().unwrap())).unbox().span(),
            isv_prod_id: U16BytesImpl::from_le_bytes(
                (*(raw_bytes.multi_pop_front::<2>().unwrap())).unbox().span()
            ),
            isv_svn: U16BytesImpl::from_le_bytes(
                (*(raw_bytes.multi_pop_front::<2>().unwrap())).unbox().span()
            ),
            reserved_4: (*(raw_bytes.multi_pop_front::<60>().unwrap())).unbox().span(),
            report_data: raw_bytes,
        }
    }

    fn to_bytes(mut self: EnclaveReport) -> Span<u8> {
        let mut raw_bytes = ArrayTrait::new();

        raw_bytes.append_span(self.cpu_svn);
        raw_bytes.append_span(self.misc_select);
        raw_bytes.append_span(self.reserved_1);
        raw_bytes.append_span(self.attributes);
        raw_bytes.append_span(self.mrenclave);
        raw_bytes.append_span(self.reserved_2);
        raw_bytes.append_span(self.mrsigner);
        raw_bytes.append_span(self.reserved_3);
        raw_bytes.append_span(U16BytesImpl::to_le_bytes(self.isv_prod_id));
        raw_bytes.append_span(U16BytesImpl::to_le_bytes(self.isv_svn));
        raw_bytes.append_span(self.reserved_4);
        raw_bytes.append_span(self.report_data);

        raw_bytes.span()
    }
}


// TD Attributes:
// [bits]   : [description]
// [0:7]    : (TUD) TD Under Debug flags.
//            If any of the bits in this group are set to 1, the TD is untrusted.
//            [0]     - (DEBUG) Defines whether the TD runs in TD debug mode (set to 1) or not (set
//            to 0).
//                      In TD debug mode, the CPU state and private memory are accessible by the
//                      host VMM.
//            [1:7]   - (RESERVED) Reserved for future TUD flags, must be 0.
// [8:31]   : (SEC) Attributes that may impact the security of the TD
//            [8:27]  - (RESERVED) Reserved for future SEC flags, must be 0.
//            [28]    - (SEPT_VE_DISABLE) Disable EPT violation conversion to #VE on TD access of
//            PENDING pages [29]    - (RESERVED) Reserved for future SEC flags, must be 0.
//            [30]    - (PKS) TD is allowed to use Supervisor Protection Keys.
//            [31]    - (KL) TD is allowed to use Key Locker.
// [32:63]  : (OTHER) Attributes that do not impact the security of the TD
//            [32:62] - (RESERVED) Reserved for future OTHER flags, must be 0.
//            [63]    - (PERFMON) TD is allowed to use Perfmon and PERF_METRICS capabilities.

// TEE_TCB_SVN:
// [bytes]  : [Name]            : [description]
// [0]      : Tdxtcbcomp01      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[0]
// [1]      : Tdxtcbcomp02      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[1]
// [2]      : Tdxtcbcomp03      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[2
// [3]      : Tdxtcbcomp04      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[3]
// [4]      : Tdxtcbcomp05      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[4]
// [5]      : Tdxtcbcomp06      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[5]
// [6]      : Tdxtcbcomp07      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[6]
// [7]      : Tdxtcbcomp08      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[7]
// [8]      : Tdxtcbcomp09      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[8]
// [9]      : Tdxtcbcomp10      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[9]
// [10]     : Tdxtcbcomp11      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[10]
// [11]     : Tdxtcbcomp12      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[11]
// [12]     : Tdxtcbcomp13      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[12]
// [13]     : Tdxtcbcomp14      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[13]
// [14]     : Tdxtcbcomp15      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[14]
// [15]     : Tdxtcbcomp16      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[15]

#[derive(Drop)]
pub struct TD10ReportBody {
    // [16 bytes]
    // Describes the TCB of TDX. (Refer to above)
    pub tee_tcb_svn: Span<u8>,
    // [48 bytes]
    // Measurement of the TDX Module.
    pub mrseam: Span<u8>,
    // [48 bytes]
    // Zero for Intel TDX Module
    pub mrsignerseam: Span<u8>,
    // [8 bytes]
    // Must be zero for TDX 1.0
    pub seam_attributes: u64,
    // [8 bytes]
    // TD Attributes (Refer to above)
    pub td_attributes: u64,
    // [8 bytes]
    // XFAM (eXtended Features Available Mask) is defined as a 64b bitmap, which has the same format
    // as XCR0 or IA32_XSS MSR.
    pub xfam: u64,
    // [48 bytes]
    // (SHA384) Measurement of the initial contents of the TD.
    pub mrtd: Span<u8>,
    // [48 bytes]
    // Software-defined ID for non-owner-defined configuration of the TD, e.g., runtime or OS
    // configuration.
    pub mrconfigid: Span<u8>,
    // [48 bytes]
    // Software-defined ID for the TD’s owner
    pub mrowner: Span<u8>,
    // [48 bytes]
    // Software-defined ID for owner-defined configuration of the TD,
    // e.g., specific to the workload rather than the runtime or OS.
    pub mrownerconfig: Span<u8>,
    // [48 bytes]
    // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr0: Span<u8>,
    // [48 bytes]
    // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr1: Span<u8>,
    // [48 bytes]
    // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr2: Span<u8>,
    // [48 bytes]
    // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr3: Span<u8>,
    // [64 bytes]
    // Additional report data.
    // The TD is free to provide 64 bytes of custom data to the REPORT.
    // This can be used to provide specific data from the TD or it can be used to hold a hash of a
    // larger block of data which is provided with the quote.
    // Note that the signature of a TD Quote covers the REPORTDATA field. As a result, the integrity
    // is protected with a key rooted in an Intel CA.
    pub report_data: Span<u8>
}

#[generate_trait]
pub impl TD10ReportBodyImpl of TD10ReportBodyTrait {
    fn from_bytes(mut raw_bytes: Span<u8>) -> TD10ReportBody {
        TD10ReportBody {
            tee_tcb_svn: (*(raw_bytes.multi_pop_front::<16>().unwrap())).unbox().span(),
            mrseam: (*(raw_bytes.multi_pop_front::<48>().unwrap())).unbox().span(),
            mrsignerseam: (*(raw_bytes.multi_pop_front::<48>().unwrap())).unbox().span(),
            seam_attributes: U64BytesImpl::from_le_bytes(
                (*(raw_bytes.multi_pop_front::<8>().unwrap())).unbox().span()
            ),
            td_attributes: U64BytesImpl::from_le_bytes(
                (*(raw_bytes.multi_pop_front::<8>().unwrap())).unbox().span()
            ),
            xfam: U64BytesImpl::from_le_bytes(
                (*(raw_bytes.multi_pop_front::<8>().unwrap())).unbox().span()
            ),
            mrtd: (*(raw_bytes.multi_pop_front::<48>().unwrap())).unbox().span(),
            mrconfigid: (*(raw_bytes.multi_pop_front::<48>().unwrap())).unbox().span(),
            mrowner: (*(raw_bytes.multi_pop_front::<48>().unwrap())).unbox().span(),
            mrownerconfig: (*(raw_bytes.multi_pop_front::<48>().unwrap())).unbox().span(),
            rtmr0: (*(raw_bytes.multi_pop_front::<48>().unwrap())).unbox().span(),
            rtmr1: (*(raw_bytes.multi_pop_front::<48>().unwrap())).unbox().span(),
            rtmr2: (*(raw_bytes.multi_pop_front::<48>().unwrap())).unbox().span(),
            rtmr3: (*(raw_bytes.multi_pop_front::<48>().unwrap())).unbox().span(),
            report_data: raw_bytes,
        }
    }

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
