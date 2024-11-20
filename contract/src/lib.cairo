use dcap_cairo::types::{QuoteHeader, TD10ReportBody, AttestationPubKey, TdxModule};
use core::starknet::secp256_trait::Signature;

#[starknet::interface]
pub trait ITdxVerifier<TContractState> {
    fn verify_tdx(
        self: @TContractState,
        quote_header: QuoteHeader,
        quote_body: TD10ReportBody,
        attestation_signature: Signature,
        attestation_pubkey: AttestationPubKey,
        tdx_module: TdxModule,
        tcb_info_svn: Span<u8>,
    ) -> bool;
}

#[starknet::contract]
mod TdxVerifier {
    use super::{QuoteHeader, TD10ReportBody, Signature, TdxModule, AttestationPubKey};
    use dcap_cairo::{verify_quote_signature, verify_tdx_module, verify_tdx_tcb};

    #[storage]
    struct Storage {}


    #[abi(embed_v0)]
    impl TdxVerifierImpl of super::ITdxVerifier<ContractState> {
        fn verify_tdx(
            self: @ContractState,
            quote_header: QuoteHeader,
            quote_body: TD10ReportBody,
            attestation_signature: Signature,
            attestation_pubkey: AttestationPubKey,
            tdx_module: TdxModule,
            tcb_info_svn: Span<u8>,
        ) -> bool {
            // Verify quote signature
            if !verify_quote_signature(
                @quote_header, @quote_body, @attestation_signature, attestation_pubkey,
            ) {
                return false;
            }

            // Verify TDX module identity
            if !verify_tdx_module(@quote_body, @tdx_module) {
                return false;
            }

            // Get TCB status from TDX module verification
            let tcb_status = verify_tdx_tcb(quote_body.tee_tcb_svn, @tdx_module);
            if tcb_status != 0 {
                return false;
            }

            true
        }
    }
}
