
pub struct IntelCollateral {
    pub tcbinfo_bytes: Option<Span<u8>>,
    pub qeidentity_bytes: Option<Span<u8>>,
    pub sgx_intel_root_ca_der: Option<Span<u8>>,
    pub sgx_tcb_signing_der: Option<Span<u8>>,
    pub sgx_pck_certchain_der: Option<Span<u8>>,
    pub sgx_intel_root_ca_crl_der: Option<Span<u8>>,
    pub sgx_pck_processor_crl_der: Option<Span<u8>>,
    pub sgx_pck_platform_crl_der: Option<Span<u8>>,
}
