#[macro_export]
macro_rules! null_terminate_bytes {
    ($bytes:expr) => ({
        let mut v = ($bytes).to_vec();
        v.push(0x00);
        v
    });
}

pub use null_terminate_bytes;

use std::io::{self, Cursor, Write};

pub fn asn1_signature_from(sig: &[u8]) -> io::Result<Vec<u8>> {
    let sig_len = sig.len();
    let half = sig_len / 2;
    let h = half as u8;

    let mut asn1 = vec![0u8; sig_len + 8];
    let mut writer = Cursor::new(&mut asn1[..]);
    writer.write(&[48, 2 * h + 6, 2, h + 1, 0])?;
    writer.write(&sig[..half])?; // r
    writer.write(&[2, h + 1, 0])?;
    writer.write(&sig[half..])?; // s

    Ok(asn1)
}

pub fn is_asn1_signature(sig: &[u8]) -> bool {
    let sig_len = sig.len();
    let seq_len = sig_len - 2;

    let int1_pos = 2;
    let int1_len = sig.get(int1_pos + 1);
    if int1_len.is_none() { return false; }
    let int1_len = *int1_len.unwrap() as usize;

    let int2_pos = int1_pos + 1 + int1_len + 1;
    let int2_len = sig.get(int2_pos + 1);
    if int2_len.is_none() { return false; }
    let int2_len = *int2_len.unwrap() as usize;

    sig[0] == 48 &&
        sig[1] as usize == seq_len &&
        sig[int1_pos] == 2 &&
        sig[int2_pos] == 2 &&
        int1_len + int2_len + 4 == seq_len
}
