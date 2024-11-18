use std::path::PathBuf;

use cairo_runner::cairo_run;
use dcap_rs::types::{collaterals::IntelCollateral, quotes::version_4::QuoteV4};
use parser::prepare_cairo_inputs;

mod cairo_runner;

fn main() {
    let quote = QuoteV4::from_bytes(include_bytes!("../../../data/quote_tdx_00806f050000.dat"));

    let mut collaterals = IntelCollateral::new();
    collaterals.set_tcbinfo_bytes(include_bytes!("../../../data/tcbinfov3_00806f050000.json"));
    collaterals.set_qeidentity_bytes(include_bytes!("../../../data/qeidentityv2_apiv4.json"));
    collaterals.set_intel_root_ca_der(include_bytes!(
        "../../../data/Intel_SGX_Provisioning_Certification_RootCA.cer"
    ));
    collaterals.set_sgx_tcb_signing_pem(include_bytes!("../../../data/signing_cert.pem"));
    collaterals
        .set_sgx_intel_root_ca_crl_der(include_bytes!("../../../data/intel_root_ca_crl.der"));
    collaterals.set_sgx_platform_crl_der(include_bytes!("../../../data/pck_platform_crl.der"));
    collaterals.set_sgx_processor_crl_der(include_bytes!("../../../data/pck_processor_crl.der"));

    let cairo_inputs = prepare_cairo_inputs(&quote, &collaterals);

    println!("Inputs: {:?}", cairo_inputs);

    let sierra_file = PathBuf::from("../../../target/dev/dcap_cairo.sierra.json");

    // cairo_run(, sierra_file);
}
