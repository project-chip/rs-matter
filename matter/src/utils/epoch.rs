use core::time::Duration;

pub type Epoch = fn() -> Duration;

pub type UtcCalendar = fn(Duration) -> UtcDate;

pub const MATTER_EPOCH_SECS: u64 = 946684800; // Seconds from 1970/01/01 00:00:00 till 2000/01/01 00:00:00 UTC

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct UtcDate {
    pub year: u16,
    pub month: u8, // 1 - 12
    pub day: u8,   // 1 - 31
    pub hour: u8,  // 0 - 23
    pub minute: u8,
    pub second: u8,
    pub millis: u16,
}

pub fn dummy_epoch() -> Duration {
    Duration::from_secs(0)
}

pub fn dummy_utc_calendar(_duration: Duration) -> UtcDate {
    Default::default()
}

#[cfg(feature = "std")]
pub fn sys_epoch() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
}

#[cfg(feature = "std")]
pub fn sys_utc_calendar(duration: Duration) -> UtcDate {
    use chrono::{Datelike, TimeZone, Timelike};
    use log::warn;

    let dt = match chrono::Utc.timestamp_opt(duration.as_secs() as _, duration.subsec_nanos()) {
        chrono::LocalResult::None => panic!("Invalid time"),
        chrono::LocalResult::Single(s) => s,
        chrono::LocalResult::Ambiguous(_, a) => {
            warn!(
                "Ambiguous time for epoch {:?}; returning latest timestamp: {a}",
                duration
            );
            a
        }
    };

    UtcDate {
        year: dt.year() as _,
        month: dt.month() as _,
        day: dt.day() as _,
        hour: dt.hour() as _,
        minute: dt.minute() as _,
        second: dt.second() as _,
        millis: (dt.nanosecond() / 1000) as _,
    }
}
