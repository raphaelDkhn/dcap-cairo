use dcap_rs::types::{
    collaterals::IntelCollateral,
    quotes::{body::QuoteBody, version_4::QuoteV4},
};
use ethnum::u256;

use crate::types::{
    AttestationPubKey, ContractInputs, QuoteHeader, Signature, TD10ReportBody, TdxModule,
    TdxModuleIdentityTcbLevel, TdxModuleTcb,
};

pub fn prepare_cairo_inputs(quote: &QuoteV4, collaterals: &IntelCollateral) -> ContractInputs {
    // Extract quote header
    let cairo_header = QuoteHeader {
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
        TD10ReportBody {
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

    // Extract ECDSA attestation signature
    let signature = {
        let sig = &quote.signature.quote_signature;
        let (r_bytes, s_bytes) = sig.split_at(32);

        // Convert both parts of the signature
        let r_u256 = u256::from_be_bytes(*try_into_array(r_bytes).unwrap());
        let s_u256 = u256::from_be_bytes(*try_into_array(s_bytes).unwrap());

        // Create the signature struct
        Signature {
            r: r_u256,
            s: s_u256,
            y_parity: false,
        }
    };

    // Get ECDSA attestation public key
    let pubkey = {
        let key = &quote.signature.ecdsa_attestation_key;
        // Split the 64 byte key into x and y coordinates (32 bytes each)
        let (x_bytes, y_bytes) = key.split_at(32);
        // Convert to big-endian representation for u256
        let x = u256::from_be_bytes(x_bytes.try_into().unwrap());
        let y = u256::from_be_bytes(y_bytes.try_into().unwrap());

        AttestationPubKey { x, y }
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
                if identity.id == expected_id {
                    identity_id = identity.id.clone(); // Get the ID from matching identity
                    for level in &identity.tcb_levels {
                        levels.push(TdxModuleIdentityTcbLevel {
                            tcb: TdxModuleTcb {
                                isvsvn: level.tcb.isvsvn,
                            },
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
        levels.sort_by(|a, b| b.tcb.isvsvn.cmp(&a.tcb.isvsvn));

        let mrsigner = hex::decode(&module.mrsigner).unwrap();
        let mut mrsigner_bytes = [0u8; 48];
        mrsigner_bytes.copy_from_slice(&mrsigner);

        TdxModule {
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

    ContractInputs {
        quote_header: cairo_header,
        quote_body: td10_body,
        attestation_signature: signature,
        attestation_pubkey: pubkey,
        tdx_module,
        tcb_info_svn,
    }
}

// Helper function to convert slice &[u8] to &[u8; 32]
fn try_into_array(slice: &[u8]) -> Result<&[u8; 32], &'static str> {
    if slice.len() == 32 {
        let ptr = slice.as_ptr() as *const [u8; 32];
        unsafe { Ok(&*ptr) }
    } else {
        Err("Slice must be exactly 32 bytes long")
    }
}
