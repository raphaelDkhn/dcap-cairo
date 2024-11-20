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

    // let is_valid = dispatcher.verify_tdx();
    // assert(is_valid == true, 'quote not valid');
}
