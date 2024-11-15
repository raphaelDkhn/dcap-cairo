
pub enum QuoteBody {
    SGXQuoteBody: EnclaveReport,
    TD10QuoteBody: TD10ReportBody
}

pub struct EnclaveReport {
    // [16 bytes]
    // Security Version of the CPU (raw value)
    pub cpu_svn: [u8; 16],

    // [4 bytes]
    // SSA Frame extended feature set. 
    // Reports what SECS.MISCSELECT settings are used in the enclave. You can limit the
    // allowed MISCSELECT settings in the sigstruct using MISCSELECT/MISCMASK.
    pub misc_select: [u8; 4],

    // [28 bytes]
    // Reserved for future use - 0
    pub reserved_1: [u8; 28],

    // [16 bytes]
    // Set of flags describing attributes of the enclave.
    // Reports what SECS.ATTRIBUTES settings are used in the enclave. The ISV can limit what
    // SECS.ATTRIBUTES can be used when loading the enclave through parameters to the SGX Signtool.
    // The Signtool will produce a SIGSTRUCT with ATTRIBUTES and ATTRIBUTESMASK 
    // which determine allowed ATTRIBUTES.
    // - For each SIGSTRUCT.ATTRIBUTESMASK bit that is set, then corresponding bit in the
    // SECS.ATTRIBUTES must match the same bit in SIGSTRUCT.ATTRIBUTES.
    pub attributes: [u8; 16],

    // [32 bytes] 
    // Measurement of the enclave. 
    // The MRENCLAVE value is the SHA256 hash of the ENCLAVEHASH field in the SIGSTRUCT.
    pub mrenclave: [u8; 32],

    // [32 bytes] 
    // Reserved for future use - 0
    pub reserved_2: [u8; 32],   

    // [32 bytes]
    // Measurement of the enclave signer. 
    // The MRSIGNER value is the SHA256 hash of the MODULUS field in the SIGSTRUCT.
    pub mrsigner: [u8; 32],    
    
    // [96 bytes]
    // Reserved for future use - 0
    pub reserved_3: [u8; 96],   

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
    pub reserved_4: [u8; 60],

    // [64 bytes]
    // Additional report data.
    // The enclave is free to provide 64 bytes of custom data to the REPORT.
    // This can be used to provide specific data from the enclave or it can be used to hold 
    // a hash of a larger block of data which is provided with the quote. 
    // The verification of the quote signature confirms the integrity of the
    // report data (and the rest of the REPORT body).
    pub report_data: [u8; 64]
}


// TD Attributes:
// [bits]   : [description]
// [0:7]    : (TUD) TD Under Debug flags. 
//            If any of the bits in this group are set to 1, the TD is untrusted.
//            [0]     - (DEBUG) Defines whether the TD runs in TD debug mode (set to 1) or not (set to 0). 
//                      In TD debug mode, the CPU state and private memory are accessible by the host VMM.
//            [1:7]   - (RESERVED) Reserved for future TUD flags, must be 0.
// [8:31]   : (SEC) Attributes that may impact the security of the TD
//            [8:27]  - (RESERVED) Reserved for future SEC flags, must be 0.
//            [28]    - (SEPT_VE_DISABLE) Disable EPT violation conversion to #VE on TD access of PENDING pages
//            [29]    - (RESERVED) Reserved for future SEC flags, must be 0.
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

pub struct TD10ReportBody {
    // [16 bytes]
    // Describes the TCB of TDX. (Refer to above)
    pub tee_tcb_svn: [u8; 16],          

    // [48 bytes]
    // Measurement of the TDX Module.
    pub mrseam: [u8; 48],               

    // [48 bytes]
    // Zero for Intel TDX Module
    pub mrsignerseam: [u8; 48],

    // [8 bytes]
    // Must be zero for TDX 1.0
    pub seam_attributes: u64,           

    // [8 bytes]
    // TD Attributes (Refer to above)
    pub td_attributes: u64,             

    // [8 bytes]
    // XFAM (eXtended Features Available Mask) is defined as a 64b bitmap, which has the same format as XCR0 or IA32_XSS MSR.
    pub xfam: u64,                      
    
    // [48 bytes]
    // (SHA384) Measurement of the initial contents of the TD.
    pub mrtd: [u8; 48],                 
    
    // [48 bytes]
    // Software-defined ID for non-owner-defined configuration of the TD, e.g., runtime or OS configuration.
    pub mrconfigid: [u8; 48],           
    
    // [48 bytes]
    // Software-defined ID for the TD’s owner
    pub mrowner: [u8; 48],             
    
    // [48 bytes]
    // Software-defined ID for owner-defined configuration of the TD, 
    // e.g., specific to the workload rather than the runtime or OS.
    pub mrownerconfig: [u8; 48],        
    
    // [48 bytes]
    // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr0: [u8; 48],                
    
    // [48 bytes]
    // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr1: [u8; 48],                
    
    // [48 bytes]
    // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr2: [u8; 48],                

    // [48 bytes]
    // (SHA384) Root of Trust for Measurement (RTM) for the TD.                    
    pub rtmr3: [u8; 48],                
    
    // [64 bytes]
    // Additional report data.
    // The TD is free to provide 64 bytes of custom data to the REPORT.
    // This can be used to provide specific data from the TD or it can be used to hold a hash of a larger block of data which is provided with the quote.
    // Note that the signature of a TD Quote covers the REPORTDATA field. As a result, the integrity is protected with a key rooted in an Intel CA.
    pub report_data: [u8; 64]
}