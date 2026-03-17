use embassy_sync::blocking_mutex::raw::NoopRawMutex;

type MatterRawMutex = NoopRawMutex;

pub type Mutex<T> = crate::utils::sync::blocking::Mutex<MatterRawMutex, T>;
pub type IfMutex<T> = crate::utils::sync::IfMutex<MatterRawMutex, T>;
pub type IfMutexGuard<'a, T> = crate::utils::sync::IfMutexGuard<'a, MatterRawMutex, T>;

pub type Signal<T> = crate::utils::sync::Signal<MatterRawMutex, T>;
pub type Notification = crate::utils::sync::Notification<MatterRawMutex>;
