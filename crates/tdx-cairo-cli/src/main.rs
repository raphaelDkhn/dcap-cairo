use std::path::PathBuf;

use cairo1_run::FuncArg;
use cairo_runner::cairo_run;
use cairo_vm::Felt252;
use dcap_rs::types::{collaterals::IntelCollateral, quotes::version_4::QuoteV4};
use parser::prepare_cairo_inputs;

mod cairo_runner;

#[derive(Debug, Clone, Default)]
struct FuncArgs(Vec<FuncArg>);

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
    // let cairo_inputs = "4 2 129 0 0 0 0 147 154 114 51 247 156 76 169 148 10 13 179 149 127 6 7 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4 1 7 0 0 0 0 0 0 0 0 0 0 0 0 0 255 201 122 136 88 118 96 251 4 225 247 200 81 48 12 150 174 11 90 70 58 196 109 3 93 22 194 217 243 109 14 209 210 55 117 188 189 39 222 178 25 227 163 204 40 2 56 149 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 268435456 393447 147 91 231 116 45 216 156 106 77 246 219 168 53 61 137 4 26 224 240 82 190 239 153 59 30 127 69 36 211 188 87 101 13 242 14 85 130 21 131 82 225 36 11 63 31 237 85 216 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 403823892856199322483292057726729294491177228149490525940610607326103366343 304915249766564773122051689299400949978501497462731030131453462381165363271 1123696221961176969549850327546470367050027401731477575998442917616651267006 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 18446744073709551615 92652517142577 92652517142577 2 291 0 [3 0 6 0 0 0 0 0 0 0 0 0 0 0 0 0]";

    let sierra_file = PathBuf::from("../../target/dev/dcap_cairo.sierra.json");

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
