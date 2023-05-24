use embassy_futures::select::{Either, Either3, Either4};

pub trait EitherUnwrap<T> {
    fn unwrap(self) -> T;
}

impl<T> EitherUnwrap<T> for Either<T, T> {
    fn unwrap(self) -> T {
        match self {
            Self::First(t) => t,
            Self::Second(t) => t,
        }
    }
}

impl<T> EitherUnwrap<T> for Either3<T, T, T> {
    fn unwrap(self) -> T {
        match self {
            Self::First(t) => t,
            Self::Second(t) => t,
            Self::Third(t) => t,
        }
    }
}

impl<T> EitherUnwrap<T> for Either4<T, T, T, T> {
    fn unwrap(self) -> T {
        match self {
            Self::First(t) => t,
            Self::Second(t) => t,
            Self::Third(t) => t,
            Self::Fourth(t) => t,
        }
    }
}
