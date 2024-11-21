use dcap_rs::types::collaterals::IntelCollateral;
use dcap_rs::types::quotes::version_4::QuoteV4;
use preprocess::parser::prepare_cairo_inputs;

use std::fs::File;
use std::io::Write;

// September 10th, 2024, 6:49am GMT
const PINNED_TIME: u64 = 1725950994;

pub fn main() {
    // Load TDX quote from binary data file
    let quote = QuoteV4::from_bytes(include_bytes!("../data/quote_tdx_00806f050000.dat"));

    // Initialize Intel collateral structure and load verification data
    let mut collaterals = IntelCollateral::new();
    collaterals.set_tcbinfo_bytes(include_bytes!("../data/tcbinfov3_00806f050000.json"));
    collaterals.set_qeidentity_bytes(include_bytes!("../data/qeidentityv2_apiv4.json"));
    collaterals.set_intel_root_ca_der(include_bytes!(
        "../data/Intel_SGX_Provisioning_Certification_RootCA.cer"
    ));
    collaterals.set_sgx_tcb_signing_pem(include_bytes!("../data/signing_cert.pem"));
    collaterals.set_sgx_intel_root_ca_crl_der(include_bytes!("../data/intel_root_ca_crl.der"));
    collaterals.set_sgx_platform_crl_der(include_bytes!("../data/pck_platform_crl.der"));
    collaterals.set_sgx_processor_crl_der(include_bytes!("../data/pck_processor_crl.der"));

    // Prepare inputs for Cairo contract
    let inputs = prepare_cairo_inputs(&quote, &collaterals, PINNED_TIME);

    // Generate Cairo code for constructor arguments
    let cairo_code = format!(
        "
            let quote_header = QuoteHeader {{
                version: {},
                att_key_type: {},
                tee_type: {},
                qe_svn: [{}].span(),
                pce_svn: [{}].span(),
                qe_vendor_id: [{}].span(),
                user_data: [{}].span()
            }};
            let quote_body = TD10ReportBody {{
                tee_tcb_svn: [{}].span(),
                mrseam: [{}].span(),
                mrsignerseam: [{}].span(),
                seam_attributes: {},
                td_attributes: {},
                xfam: {},
                mrtd: [{}].span(),
                mrconfigid: [{}].span(),
                mrowner: [{}].span(),
                mrownerconfig: [{}].span(),
                rtmr0: [{}].span(),
                rtmr1: [{}].span(),
                rtmr2: [{}].span(),
                rtmr3: [{}].span(),
                report_data: [{}].span(),
            }};
            let attestation_signature = Signature {{ 
                r: {}, 
                s: {}, 
                y_parity: {} 
            }};
            let attestation_pubkey = PubKey {{ 
                x: {}, 
                y: {} 
            }};
            let tdx_module = TdxModule {{
                mrsigner: [{}].span(),
                attributes: {},
                attributes_mask: {},
                identity_id: '{}',
                expected_id: '{}',
                tcb_levels: {}
            }};
            let tcb_info_svn = [{}].span();
            let dates = Dates {{
                current_time: {},
                issue_date_seconds: {},
                next_update_seconds: {}
            }};
            let enclave_identity = EnclaveIdentityV2 {{
                signature: Signature {{ 
                    r: {}, 
                    s: {}, 
                    y_parity: {} 
                }},
                data: [{}].span()
            }};
            let sgx_signing_pubkey = PubKey {{
                x: {},
                y: {}
            }};
        ",
        // Quote Header
        inputs.quote_header.version,
        inputs.quote_header.att_key_type,
        inputs.quote_header.tee_type,
        inputs.quote_header.qe_svn.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_header.pce_svn.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_header.qe_vendor_id.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_header.user_data.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        // TD10 Report Body
        inputs.quote_body.tee_tcb_svn.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_body.mrseam.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_body.mrsignerseam.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_body.seam_attributes,
        inputs.quote_body.td_attributes,
        inputs.quote_body.xfam,
        inputs.quote_body.mrtd.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_body.mrconfigid.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_body.mrowner.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_body.mrownerconfig.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_body.rtmr0.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_body.rtmr1.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_body.rtmr2.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_body.rtmr3.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.quote_body.report_data.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        // Signature
        inputs.attestation_signature.r,
        inputs.attestation_signature.s,
        inputs.attestation_signature.y_parity,
        // Public Key
        inputs.attestation_pubkey.x,
        inputs.attestation_pubkey.y,
        // TDX Module
        inputs.tdx_module.mrsigner.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.tdx_module.attributes,
        inputs.tdx_module.attributes_mask,
        inputs.tdx_module.identity_id,
        inputs.tdx_module.expected_id,
        format!("[{}].span()", 
            inputs.tdx_module.tcb_levels.iter()
                .map(|level| format!("TdxModuleIdentityTcbLevel {{ tcb: TdxModuleTcb {{ isvsvn: {} }}, tcb_status: {} }}", 
                    level.tcb.isvsvn, level.tcb_status))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        // TCB Info SVN
        inputs.tcb_info_svn.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        // Enclave Identity
        inputs.dates.current_time,
        inputs.dates.issue_date_seconds,
        inputs.dates.next_update_seconds,
        inputs.enclave_identity.signature.r,
        inputs.enclave_identity.signature.s,
        inputs.enclave_identity.signature.y_parity,
        inputs.enclave_identity.data.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", "),
        inputs.sgx_signing_pubkey.x,
        inputs.sgx_signing_pubkey.y
    );

    let path = "test_data.txt";
    let mut file = File::create(path).expect("Could not create file");

    // Write the cairo code to the file
    file.write_all(cairo_code.as_bytes())
        .expect("Could not write to file");
}
