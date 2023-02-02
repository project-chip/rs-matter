use core::time::Duration;

pub type Epoch = fn() -> Duration;

pub fn dummy_epoch() -> Duration {
    Duration::from_secs(0)
}

#[cfg(feature = "std")]
pub fn sys_epoch() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
}
