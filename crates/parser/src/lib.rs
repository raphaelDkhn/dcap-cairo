use dcap_rs::types::{
    collaterals::IntelCollateral,
    quotes::{body::QuoteBody, version_4::QuoteV4},
};
use types::{
    CairoECDSASignature, CairoQuoteHeader, CairoTD10Report, CairoTDXModule, CairoVerificationInputs,
};

pub mod types;

pub fn prepare_cairo_inputs(
    quote_bytes: &[u8],
    collaterals: &IntelCollateral,
    min_isvsvn: u8,
) -> CairoVerificationInputs {
    // 1. Parse the quote using Automata's library
    let quote = QuoteV4::from_bytes(quote_bytes);

    // 2. Extract quote header
    let cairo_header = CairoQuoteHeader {
        version: quote.header.version,
        att_key_type: quote.header.att_key_type,
        tee_type: quote.header.tee_type,
        qe_svn: quote.header.qe_svn.to_vec(),
        pce_svn: quote.header.pce_svn.to_vec(),
        qe_vendor_id: quote.header.qe_vendor_id.to_vec(),
        user_data: quote.header.user_data.to_vec(),
    };

    // 3. Extract TD10 report body
    let td10_body = if let QuoteBody::TD10QuoteBody(body) = quote.quote_body {
        CairoTD10Report {
            tee_tcb_svn: body.tee_tcb_svn.to_vec(),
            mrseam: body.mrseam.to_vec(),
            mrsignerseam: body.mrsignerseam.to_vec(),
            seam_attributes: body.seam_attributes,
            td_attributes: body.td_attributes,
            xfam: body.xfam,
            mrtd: body.mrtd.to_vec(),
            mrconfigid: body.mrconfigid.to_vec(),
            mrowner: body.mrowner.to_vec(),
            mrownerconfig: body.mrownerconfig.to_vec(),
            rtmr0: body.rtmr0.to_vec(),
            rtmr1: body.rtmr1.to_vec(),
            rtmr2: body.rtmr2.to_vec(),
            rtmr3: body.rtmr3.to_vec(),
            report_data: body.report_data.to_vec(),
        }
    } else {
        panic!("Not a TD10 quote body");
    };

    // 4. Extract ECDSA signature
    let signature = {
        let sig = &quote.signature.quote_signature;
        let (r, s) = sig.split_at(32);

        // Convert to felt252-compatible hex strings
        let r_hex = format!("0x{}", hex::encode(r));
        let s_hex = format!("0x{}", hex::encode(s));

        CairoECDSASignature { r: r_hex, s: s_hex }
    };

    // 5. Get attestation public key
    let pubkey = {
        let key = &quote.signature.ecdsa_attestation_key;
        format!("0x{}", hex::encode(key))
    };

    // 6. Extract TDX module info from TCBInfo
    let tcbinfo_v3 = collaterals.get_tcbinfov3();
    let tdx_module = if let Some(module) = &tcbinfo_v3.tcb_info.tdx_module {
        let mrsigner = hex::decode(&module.mrsigner).unwrap();
        let mut mrsigner_bytes = [0u8; 48];
        mrsigner_bytes.copy_from_slice(&mrsigner);

        CairoTDXModule {
            mrsigner: mrsigner_bytes.to_vec(),
            attributes: u64::from_str_radix(&module.attributes, 16).unwrap(),
            attributes_mask: u64::from_str_radix(&module.attributes_mask, 16).unwrap(),
        }
    } else {
        panic!("No TDX module in TCBInfo");
    };

    // 7. Get TCB SVN values for comparison
    let tcb_info_svn = if let Some(tcb_level) = tcbinfo_v3.tcb_info.tcb_levels.first() {
        if let Some(tdx_components) = &tcb_level.tcb.tdxtcbcomponents {
            tdx_components.iter().map(|comp| comp.svn as u8).collect()
        } else {
            Vec::new()
        }
    } else {
        panic!("No TCB levels found");
    };

    CairoVerificationInputs {
        quote_header: cairo_header,
        quote_body: td10_body,
        attestation_signature: signature,
        attestation_pubkey: pubkey,
        tdx_module,
        tcb_info_svn,
        min_isvsvn,
    }
}
