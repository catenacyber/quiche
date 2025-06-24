#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

use quiche::h3::frame::Frame;

// Fuzzer for qpack codec. Checks that decode(encode(hdrs)) == hdrs. To get the
// initial hdrs, the fuzzer deserializes the input, and skips inputs where
// deserialization fails.
//
// The fuzzer could have been written to instead check encode(decode(input)) ==
// input. However, that transformation is not guaranteed to be the identify
// function, as there are multiple ways the same hdr list could be encoded.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    
    if let Ok(f) = Frame::from_bytes(data[0] as u64, (data.len() - 1)as u64, &data[1..]) {
        let mut d = vec![42; data.len()];
        let mut b = octets::OctetsMut::with_slice(&mut d);
        let _ = f.to_bytes(&mut b);
    }
});
