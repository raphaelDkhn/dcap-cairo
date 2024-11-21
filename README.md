# TDX Cairo Verifier [WIP]

A quote verifier smart contract for [Intel's TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html), implemented in Cairo.
It enables trust-minimized validation of TEE quotes without relying on [attestation authority services](https://docs.trustauthority.intel.com/main/articles/introduction.html).

> ⚠️ SECURITY WARNING: This is experimental software and under development. Do not use in production.

## Prerequise

- Rust
- [Scarb](https://docs.swmansion.com/scarb/download.html) 2.8.4
- [Starknet Foundry](https://foundry-rs.github.io/starknet-foundry/index.html)

## Run tests

```
$ cd contract
$ snforge test
```

## TDX Validations

| Validation                              | Status |
| --------------------------------------- | ------ |
| Verify attestation signature            | ✅     |
| Validate enclave entity                 | ✅     |
| Validate enclave entity                 | ✅     |
| Verify TDX module identity              | ✅     |
| Verify TCB status                       | ✅     |
| Verify certificate                      | ⏳     |
| Verify certificate                      | ⏳     |
| Verify QEReport                         | ⏳     |
| Verify certificate chain                | ⏳     |
| Verify the signature for qe report data | ⏳     |

## Credits

Thanks to [Automata](https://www.ata.network/) for the [dcap-rs](https://github.com/automata-network/dcap-rs) library 🫶.
