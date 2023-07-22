pub type Rand = fn(&mut [u8]);

pub fn dummy_rand(_buf: &mut [u8]) {}

#[cfg(feature = "std")]
pub fn sys_rand(buf: &mut [u8]) {
    use rand::{thread_rng, RngCore};

    thread_rng().fill_bytes(buf);
}
