use crate::types::{VerifiedOutput, quotes::{v4::{QuoteV4}, CertDataType}, collaterals::IntelCollateral};
use super::check_quote_header;

pub fn verify_quote_dcapv4(
    quote: @QuoteV4, collaterals: @IntelCollateral, current_time: u64,
) // -> VerifiedOutput 
{
    assert!(check_quote_header(quote.header, 4), "invalid quote header");


    // we'll now proceed to verify the qe
    let qe_cert_data_v4 = quote.signature.qe_cert_data;

    // // right now we just handle type 6, which contains the QEReport, QEReportSignature, QEAuthData and another CertData
    // let qe_report_cert_data = if let CertDataType::QeReportCertData(qe_report_cert_data) = 
    //     qe_cert_data_v4.get_cert_data() 
    // {
    //     qe_report_cert_data
    // } else {
    //     panic!("Unsupported CertDataType in QuoteSignatureDataV4");
    // };

}
