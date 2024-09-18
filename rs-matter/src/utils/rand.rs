pub type Rand = fn(&mut [u8]);

pub fn dummy_rand(buf: &mut [u8]) {
    // rust-crypto's KeyPair::new(rand) blocks on a zeroed buffer
    // Trick it a bit, as we use `dummy_rand` in our no_std tests
    for i in 0..buf.len() {
        buf[i] = (i % 256) as u8;
    }
}

#[cfg(feature = "std")]
pub fn sys_rand(buf: &mut [u8]) {
    use rand::{thread_rng, RngCore};

    thread_rng().fill_bytes(buf);
}
