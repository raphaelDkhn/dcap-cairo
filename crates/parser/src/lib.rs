use cairo_vm::Felt252;
use dcap_rs::types::{
    collaterals::IntelCollateral,
    quotes::{body::QuoteBody, version_4::QuoteV4},
};
use types::{
    CairoECDSASignature, CairoQuoteHeader, CairoTD10Report, CairoTDXModule, CairoTdxModuleTcb,
    CairoTdxModuleTcbLevel, CairoVerificationInputs,
};

pub mod types;

pub fn prepare_cairo_inputs(quote: &QuoteV4, collaterals: &IntelCollateral) -> String {
    // Extract quote header
    let cairo_header = CairoQuoteHeader {
        version: quote.header.version,
        att_key_type: quote.header.att_key_type,
        tee_type: quote.header.tee_type,
        qe_svn: quote.header.qe_svn.to_vec(),
        pce_svn: quote.header.pce_svn.to_vec(),
        qe_vendor_id: quote.header.qe_vendor_id.to_vec(),
        user_data: quote.header.user_data.to_vec(),
    };

    // Extract TD10 report body
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

    // Extract ECDSA signature
    let signature = {
        let sig = &quote.signature.quote_signature;
        let (r, s) = sig.split_at(32);

        // Convert to felt252-compatible hex strings
        let r_hex = format!("0x{}", hex::encode(r));
        let s_hex = format!("0x{}", hex::encode(s));

        CairoECDSASignature { r: r_hex, s: s_hex }
    };

    // Get attestation public key
    let pubkey = {
        let key = &quote.signature.ecdsa_attestation_key;
        let (x, _y) = key.split_at(32); // Only need x coordinate
        format!("0x{}", hex::encode(x))
    };

    // Extract TDX module info from TCBInfo
    let tcbinfo_v3 = collaterals.get_tcbinfov3();
    let tdx_module = if let Some(module) = &tcbinfo_v3.tcb_info.tdx_module {
        // Get version from quote's TEE TCB SVN
        let tdx_module_version = if let QuoteBody::TD10QuoteBody(ref body) = quote.quote_body {
            body.tee_tcb_svn[1]
        } else {
            panic!("Not a TD10 quote body");
        };

        // Pre-format the expected module ID
        let expected_id = format!("TDX_{:02x}", tdx_module_version);

        // Collect TCB levels and get module ID for the matching version
        let mut levels = Vec::new();
        let mut identity_id = String::new();

        if let Some(identities) = &tcbinfo_v3.tcb_info.tdx_module_identities {
            for identity in identities {
                // Only include levels from matching module version
                if identity.id == expected_id {
                    identity_id = identity.id.clone(); // Get the ID from matching identity
                    for level in &identity.tcb_levels {
                        levels.push(CairoTdxModuleTcbLevel {
                            tcb: CairoTdxModuleTcb {
                                isvsvn: level.tcb.isvsvn,
                            },
                            tcb_date: level.tcb_date.clone(),
                            tcb_status: match level.tcb_status.as_str() {
                                "UpToDate" => 0,
                                "SWHardeningNeeded" => 1,
                                "ConfigurationNeeded" => 2,
                                "ConfigurationAndSWHardeningNeeded" => 3,
                                "OutOfDate" => 4,
                                "OutOfDateConfigurationNeeded" => 5,
                                "Revoked" => 6,
                                _ => 7, // UNRECOGNIZED
                            },
                        });
                    }
                }
            }
        }

        let mrsigner = hex::decode(&module.mrsigner).unwrap();
        let mut mrsigner_bytes = [0u8; 48];
        mrsigner_bytes.copy_from_slice(&mrsigner);

        CairoTDXModule {
            mrsigner: mrsigner_bytes.to_vec(),
            attributes: u64::from_str_radix(&module.attributes, 16).unwrap(),
            attributes_mask: u64::from_str_radix(&module.attributes_mask, 16).unwrap(),
            identity_id, // Get ID from matching identity
            expected_id, // Expected ID based on version
            tcb_levels: levels,
        }
    } else {
        panic!("No TDX module in TCBInfo");
    };

    // Get TCB SVN values for comparison
    let tcb_info_svn = if let Some(tcb_level) = tcbinfo_v3.tcb_info.tcb_levels.first() {
        if let Some(tdx_components) = &tcb_level.tcb.tdxtcbcomponents {
            tdx_components.iter().map(|comp| comp.svn as u8).collect()
        } else {
            Vec::new()
        }
    } else {
        panic!("No TCB levels found");
    };

    let cairo_inputs = CairoVerificationInputs {
        quote_header: cairo_header,
        quote_body: td10_body,
        attestation_signature: signature,
        attestation_pubkey: pubkey,
        tdx_module,
        tcb_info_svn,
    };

    serialize_inputs(cairo_inputs)
}

fn serialize_inputs(inputs: CairoVerificationInputs) -> String {
    let mut serialized: Vec<String> = vec![];

    // Serialize QuoteHeader
    let quote_header = inputs.quote_header;
    serialized.push(quote_header.version.to_string());
    serialized.push(quote_header.att_key_type.to_string());
    serialized.push(quote_header.tee_type.to_string());
    quote_header
        .qe_svn
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_header
        .pce_svn
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_header
        .qe_vendor_id
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_header
        .user_data
        .iter()
        .for_each(|e| serialized.push(e.to_string()));

    // Serialize TD10ReportBody
    let quote_body = inputs.quote_body;
    quote_body
        .tee_tcb_svn
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_body
        .mrseam
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_body
        .mrsignerseam
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    serialized.push(quote_body.seam_attributes.to_string());
    serialized.push(quote_body.td_attributes.to_string());
    serialized.push(quote_body.xfam.to_string());
    quote_body
        .mrtd
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_body
        .mrconfigid
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_body
        .mrowner
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_body
        .mrownerconfig
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_body
        .rtmr0
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_body
        .rtmr1
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_body
        .rtmr2
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_body
        .rtmr3
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    quote_body
        .report_data
        .iter()
        .for_each(|e| serialized.push(e.to_string()));

    // Serialize ECDSASignature
    let attestation_signature = inputs.attestation_signature;
    serialized.push(
        Felt252::from_hex(&attestation_signature.r)
            .unwrap()
            .to_string(),
    );
    serialized.push(
        Felt252::from_hex(&attestation_signature.s)
            .unwrap()
            .to_string(),
    );

    // Serialize attestation pubkey
    serialized.push(
        Felt252::from_hex(&inputs.attestation_pubkey)
            .unwrap()
            .to_string(),
    );

    // Serialize TDXModule
    let tdx_module = inputs.tdx_module;
    tdx_module
        .mrsigner
        .iter()
        .for_each(|e| serialized.push(e.to_string()));
    serialized.push(tdx_module.attributes.to_string());
    serialized.push(tdx_module.attributes_mask.to_string());
    serialized.push(
        Felt252::from_hex(&format!("0x{}", hex::encode(tdx_module.identity_id)))
            .unwrap()
            .to_string(),
    );
    serialized.push(
        Felt252::from_hex(&format!("0x{}", hex::encode(tdx_module.expected_id)))
            .unwrap()
            .to_string(),
    );
    tdx_module.tcb_levels.iter().for_each(|e| {
        serialized.push(e.tcb.isvsvn.to_string());
        serialized.push(Felt252::from_hex("0x123").unwrap().to_string());
        serialized.push(e.tcb_status.to_string());
    });

    // Serialize tcb info svn
    inputs
        .tcb_info_svn
        .iter()
        .for_each(|e| serialized.push(e.to_string()));

    serialized.join(" ")
}
