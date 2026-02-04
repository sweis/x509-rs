#![no_main]

use libfuzzer_sys::fuzz_target;
use xcert_lib::{der_to_pem, parse_cert, parse_der, pem_to_der};

fuzz_target!(|data: &[u8]| {
    // If data parses as DER, roundtrip through PEM and back
    if let Ok(cert1) = parse_der(data) {
        let pem = der_to_pem(data);
        if let Ok(der_back) = pem_to_der(pem.as_bytes()) {
            if let Ok(cert2) = parse_der(&der_back) {
                // The serial number should survive the roundtrip
                assert_eq!(
                    cert1.serial_hex(),
                    cert2.serial_hex(),
                    "serial mismatch after roundtrip"
                );
            }
        }
    }

    // If data parses as PEM, try extracting DER
    if let Ok(_cert) = parse_cert(data) {
        // Success - the parser handled it
    }
});
