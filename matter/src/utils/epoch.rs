use core::time::Duration;

pub type Epoch = fn() -> Duration;

pub const MATTER_EPOCH_SECS: u64 = 946684800; // Seconds from 1970/01/01 00:00:00 till 2000/01/01 00:00:00 UTC

pub fn dummy_epoch() -> Duration {
    Duration::from_secs(0)
}

#[cfg(feature = "std")]
pub fn sys_epoch() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
}
