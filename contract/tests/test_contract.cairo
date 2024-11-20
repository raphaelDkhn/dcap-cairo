use starknet::ContractAddress;

use snforge_std::{declare, ContractClassTrait, DeclareResultTrait};

use tdx_verifier::ITdxVerifierDispatcher;
use tdx_verifier::ITdxVerifierDispatcherTrait;

fn deploy_contract(name: ByteArray) -> ContractAddress {
    let contract = declare(name).unwrap().contract_class();
    let (contract_address, _) = contract.deploy(@ArrayTrait::new()).unwrap();
    contract_address
}

#[test]
fn test_verify_tdx() {
    let contract_address = deploy_contract("TdxVerifier");
    let dispatcher = ITdxVerifierDispatcher { contract_address };

    parse_tdx!(
        "contract/data/quote_tdx_00806f050000.dat",
        "contract/data/tcbinfov3_00806f050000.json",
        "contract/data/qeidentityv2_apiv4.json", 
        "contract/data/Intel_SGX_Provisioning_Certification_RootCA.cer",
        "contract/data/signing_cert.pem",
        "contract/data/intel_root_ca_crl.der",
        "contract/data/pck_platform_crl.der", 
        "contract/data/pck_processor_crl.der"
    );

    // let is_valid = dispatcher.verify_tdx();
    // assert(is_valid == true, 'quote not valid');
}
