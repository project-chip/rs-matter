pub type Rand = fn(&mut [u8]);

pub fn dummy_rand(_buf: &mut [u8]) {}
