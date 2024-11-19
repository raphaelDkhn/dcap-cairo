use std::env;

use cairo1_run::FuncArg;
use cairo_runner::cairo_run;
use cairo_vm::Felt252;
use dcap_rs::types::{collaterals::IntelCollateral, quotes::version_4::QuoteV4};
use parser::prepare_cairo_inputs;

mod cairo_runner;

#[derive(Debug, Clone, Default)]
struct FuncArgs(Vec<FuncArg>);

fn main() {
    // Load TDX quote from binary data file
    let quote = QuoteV4::from_bytes(include_bytes!("../../../data/quote_tdx_00806f050000.dat"));

    // Initialize Intel collateral structure and load verification data
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

    // Prepare inputs for Cairo verification program
    let cairo_inputs = prepare_cairo_inputs(&quote, &collaterals);

    // Get path to Sierra TDX verifier program file
    let exe_path = env::current_exe().expect("Failed to get the current executable path");
    let exe_dir = exe_path
        .parent()
        .expect("Failed to get the executable directory");
    let sierra_file = exe_dir.join("../../target/dev/tdx_cairo_verifier.sierra.json");

    // Run Cairo program with processed inputs
    let res = cairo_run(&process_args(&cairo_inputs).unwrap().0, sierra_file);

    println!("Res: {:?}", res);
}

fn process_array<'a>(iter: &mut impl Iterator<Item = &'a str>) -> Result<FuncArg, String> {
    let mut array = vec![];
    for value in iter {
        match value {
            "]" => break,
            _ => array.push(
                Felt252::from_dec_str(value)
                    .map_err(|_| format!("\"{}\" is not a valid felt", value))?,
            ),
        }
    }
    Ok(FuncArg::Array(array))
}

fn process_args(value: &str) -> Result<FuncArgs, String> {
    let mut args = Vec::new();
    // Split input string into numbers and array delimiters
    let mut input = value.split_ascii_whitespace().flat_map(|mut x| {
        // We don't have a way to split and keep the separate delimiters so we do it manually
        let mut res = vec![];
        if let Some(val) = x.strip_prefix('[') {
            res.push("[");
            x = val;
        }
        if let Some(val) = x.strip_suffix(']') {
            if !val.is_empty() {
                res.push(val)
            }
            res.push("]")
        } else if !x.is_empty() {
            res.push(x)
        }
        res
    });
    // Process iterator of numbers & array delimiters
    while let Some(value) = input.next() {
        match value {
            "[" => args.push(process_array(&mut input)?),
            _ => args.push(FuncArg::Single(
                Felt252::from_dec_str(value)
                    .map_err(|_| format!("\"{}\" is not a valid felt", value))?,
            )),
        }
    }
    Ok(FuncArgs(args))
}
