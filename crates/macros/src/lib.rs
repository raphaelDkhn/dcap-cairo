use cairo_lang_macro::{inline_macro, ProcMacroResult, TokenStream};
use cairo_lang_parser::utils::SimpleParserDatabase;
use cairo_lang_syntax::node::kind::SyntaxKind::Arg;
use dcap_rs::types::collaterals::IntelCollateral;
use dcap_rs::types::quotes::version_4::QuoteV4;
use preprocess::parser::prepare_cairo_inputs;
use std::env;

#[inline_macro]
pub fn parse_tdx(token_stream: TokenStream) -> ProcMacroResult {
    let db = SimpleParserDatabase::default();
    let (parsed, _diag) = db.parse_virtual_with_diagnostics(token_stream);

    // Extract file paths from macro arguments and clean them
    let paths: Vec<String> = parsed
        .descendants(&db)
        .filter_map(|node| {
            if let Arg = node.kind(&db) {
                Some(node.get_text(&db).trim().replace("\"", "").to_string())
            } else {
                None
            }
        })
        .collect();

    if paths.len() != 8 {
        return ProcMacroResult::new(TokenStream::empty())
            .with_diagnostics(cairo_lang_macro::Diagnostic::error("Expected 8 file paths").into());
    }

    // Get the project root directory (two levels up from manifest dir)
    let project_root = env::current_dir()
        .unwrap()
        .parent() // up from contract
        .unwrap()
        .to_path_buf();

    let read_file = |rel_path: &str| -> Vec<u8> {
        let abs_path = project_root.join(rel_path);
        std::fs::read(&abs_path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", abs_path.display(), e))
    };

    // Read quote file
    let quote_bytes = read_file(&paths[0]);
    let quote = QuoteV4::from_bytes(&quote_bytes);

    // Initialize collaterals
    let mut collaterals = IntelCollateral::new();
    collaterals.set_tcbinfo_bytes(&read_file(&paths[1]));
    collaterals.set_qeidentity_bytes(&read_file(&paths[2]));
    collaterals.set_intel_root_ca_der(&read_file(&paths[3]));
    collaterals.set_sgx_tcb_signing_pem(&read_file(&paths[4]));
    collaterals.set_sgx_intel_root_ca_crl_der(&read_file(&paths[5]));
    collaterals.set_sgx_platform_crl_der(&read_file(&paths[6]));
    collaterals.set_sgx_processor_crl_der(&read_file(&paths[7]));

    // Prepare inputs for Cairo contract
    let inputs = prepare_cairo_inputs(&quote, &collaterals);

    // Generate Cairo code for constructor arguments
    let cairo_code = format!(
        "dispatcher.verify_tdx(
            QuoteHeader {{
                version: {},
                att_key_type: {},
                tee_type: {},
                qe_svn: array![{}].span(),
                pce_svn: array![{}].span(),
                qe_vendor_id: array![{}].span(),
                user_data: array![{}].span()
            }},
            TD10ReportBody {{
                tee_tcb_svn: array![{}].span(),
                mrseam: array![{}].span(),
                mrsignerseam: array![{}].span(),
                seam_attributes: {},
                td_attributes: {},
                xfam: {},
                mrtd: array![{}].span(),
                mrconfigid: array![{}].span(),
                mrowner: array![{}].span(),
                mrownerconfig: array![{}].span(),
                rtmr0: array![{}].span(),
                rtmr1: array![{}].span(),
                rtmr2: array![{}].span(),
                rtmr3: array![{}].span(),
                report_data: array![{}].span(),
            }},
            Signature {{ 
                r: {}, 
                s: {}, 
                y_parity: {} 
            }},
            AttestationPubKey {{ 
                x: {}, 
                y: {} 
            }},
            TdxModule {{
                mrsigner: array![{}].span(),
                attributes: {},
                attributes_mask: {},
                identity_id: \"{}\",
                expected_id: \"{}\",
                tcb_levels: {}
            }},
            array![{}].span()
        )",
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
        format!("array![{}].span()", 
            inputs.tdx_module.tcb_levels.iter()
                .map(|level| format!("TdxModuleIdentityTcbLevel {{ tcb: TdxModuleTcb {{ isvsvn: {} }}, tcb_status: {} }}", 
                    level.tcb.isvsvn, level.tcb_status))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        // TCB Info SVN
        inputs.tcb_info_svn.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ")
    );

    ProcMacroResult::new(TokenStream::new(cairo_code))
}
