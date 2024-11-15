pub mod v4;
pub mod body;

pub struct QuoteHeader {
    // [2 bytes]
    // Version of the quote data structure - 4, 5
    pub version: u16,
    // [2 bytes]
    // Type of the Attestation Key used by the Quoting Enclave -
    // 2 (ECDSA-256-with-P-256 curve)
    // 3 (ECDSA-384-with-P-384 curve)
    pub att_key_type: u16,
    // [4 bytes]
    // TEE for this Attestation
    // 0x00000000: SGX
    // 0x00000081: TDX
    pub tee_type: u32,
    // [2 bytes]
    // Security Version of the Quoting Enclave - 1 (only applicable for SGX Quotes)
    pub qe_svn: [u8; 2],
    // [2 bytes]
    // Security Version of the PCE - 0 (only applicable for SGX Quotes)
    pub pce_svn: [u8; 2],
    // [16 bytes]
    // Unique identifier of the QE Vendor.
    // Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
    // Note: Each vendor that decides to provide a customized Quote data structure should have
    // unique ID.
    pub qe_vendor_id: [u8; 16],
    // [20 bytes]
    // Custom user-defined data. For the Intel® SGX and TDX DCAP Quote Generation Libraries,
    // the first 16 bytes contain a Platform Identifier that is used to link a PCK Certificate
    // to an Enc(PPID).
    pub user_data: [u8; 20]
}

pub struct CertData {
    // [2 bytes]
    // Determines type of data required to verify the QE Report Signature in the Quote Signature Data structure. 
    // 1 - (PCK identifier: PPID in plain text, CPUSVN, and PCESVN)
    // 2 - (PCK identifier: PPID encrypted using RSA-2048-OAEP, CPUSVN, and PCESVN)
    // 3 - (PCK identifier: PPID encrypted using RSA-2048-OAEP, CPUSVN, PCESVN, and QEID)
    // 4 - (PCK Leaf Certificate in plain text; currently not supported)
    // 5 - (Concatenated PCK Cert Chain)
    // 6 - (QE Report Certification Data)
    // 7 - (PLATFORM_MANIFEST; currently not supported)
    pub cert_data_type: u16,

    // [4 bytes]
    // Size of Certification Data field.
    pub cert_data_size: u32,        
                        
    // [variable bytes]
    // Data required to verify the QE Report Signature depending on the value of the Certification Data Type:
    // 1: Byte array that contains concatenation of PPID, CPUSVN, PCESVN (LE), PCEID (LE).
    // 2: Byte array that contains concatenation of PPID encrypted using RSA-2048-OAEP, CPUSVN, PCESVN (LE), PCEID (LE).
    // 3: Byte array that contains concatenation of PPID encrypted using RSA-3072-OAEP, CPUSVN, PCESVN (LE), PCEID (LE).
    // 4: PCK Leaf Certificate
    // 5: Concatenated PCK Cert Chain (PEM formatted). PCK Leaf Cert || Intermediate CA Cert || Root CA Cert 
    // 6: QE Report Certification Data
    // 7: PLATFORM_MANIFEST
    pub cert_data: Span<u8>,            
}