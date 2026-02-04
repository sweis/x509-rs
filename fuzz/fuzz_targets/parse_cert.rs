#![no_main]

use libfuzzer_sys::fuzz_target;
use xcert_lib::{parse_cert, DigestAlgorithm};

fuzz_target!(|data: &[u8]| {
    // Try parsing with auto-detection.
    // The parser must never panic, regardless of input.
    if let Ok(cert) = parse_cert(data) {
        // If parsing succeeds, exercise all field accessors
        let _ = cert.subject_string();
        let _ = cert.issuer_string();
        let _ = cert.serial_hex();
        let _ = cert.not_before_string();
        let _ = cert.not_after_string();
        let _ = cert.fingerprint(DigestAlgorithm::Sha256);
        let _ = cert.public_key_pem();
        let _ = cert.modulus_hex();
        let _ = cert.emails();
        let _ = cert.san_entries();
        let _ = cert.ocsp_urls();
        let _ = cert.key_usage();
        let _ = cert.ext_key_usage();

        // Exercise display and JSON
        let _ = xcert_lib::display_text(&cert, true);
        let _ = xcert_lib::to_json(&cert);

        // Exercise checks
        let _ = xcert_lib::check_expiry(&cert, 0);
        let _ = xcert_lib::check_host(&cert, "example.com");
        let _ = xcert_lib::check_email(&cert, "test@example.com");
        let _ = xcert_lib::check_ip(&cert, "1.2.3.4");
    }
});
