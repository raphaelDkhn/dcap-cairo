# TDX Cairo Verifier

A quote verifier for [Intel's TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html), implemented in Cairo. 
It enables trust-minimized validation of TEE quotes without relying on [attestation authority services](https://docs.trustauthority.intel.com/main/articles/introduction.html).

> ⚠️ SECURITY WARNING: This is experimental software and under development. Do not use in production.

## Prerequisites

Before you begin, ensure you have the following installed:
- Rust
- [Scarb](https://docs.swmansion.com/scarb/download.html#preview-version) version 2.8.4

## Compiling the Cairo Program

To compile the Cairo program, run the following command in your terminal:

```shell
scarb build
```

## Running the Example
Execute the example application by running:

```shell
cargo run
```

## Credits
Thanks to [Automata](https://www.ata.network/) for the [dcap-rs](https://github.com/automata-network/dcap-rs) library 🫶.