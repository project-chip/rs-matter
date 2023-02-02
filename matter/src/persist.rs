/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

use crate::error::Error;

pub trait Psm {
    fn set_kv_slice(&mut self, key: &str, val: &[u8]) -> Result<(), Error>;
    fn get_kv_slice<'a>(&self, key: &str, buf: &'a mut [u8]) -> Result<&'a [u8], Error>;

    fn set_kv_u64(&mut self, key: &str, val: u64) -> Result<(), Error>;
    fn get_kv_u64(&self, key: &str) -> Result<u64, Error>;

    fn remove(&mut self, key: &str) -> Result<(), Error>;
}

impl<T> Psm for &mut T
where
    T: Psm,
{
    fn set_kv_slice(&mut self, key: &str, val: &[u8]) -> Result<(), Error> {
        (**self).set_kv_slice(key, val)
    }

    fn get_kv_slice<'a>(&self, key: &str, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        (**self).get_kv_slice(key, buf)
    }

    fn set_kv_u64(&mut self, key: &str, val: u64) -> Result<(), Error> {
        (**self).set_kv_u64(key, val)
    }

    fn get_kv_u64(&self, key: &str) -> Result<u64, Error> {
        (**self).get_kv_u64(key)
    }

    fn remove(&mut self, key: &str) -> Result<(), Error> {
        (**self).remove(key)
    }
}

#[cfg(feature = "nightly")]
pub mod asynch {
    use crate::error::Error;

    use super::Psm;

    pub trait AsyncPsm {
        async fn set_kv_slice<'a>(&'a mut self, key: &'a str, val: &'a [u8]) -> Result<(), Error>;
        async fn get_kv_slice<'a, 'b>(
            &'a self,
            key: &'a str,
            buf: &'b mut [u8],
        ) -> Result<&'b [u8], Error>;

        async fn set_kv_u64<'a>(&'a mut self, key: &'a str, val: u64) -> Result<(), Error>;
        async fn get_kv_u64<'a>(&'a self, key: &'a str) -> Result<u64, Error>;

        async fn remove<'a>(&'a mut self, key: &'a str) -> Result<(), Error>;
    }

    impl<T> AsyncPsm for &mut T
    where
        T: AsyncPsm,
    {
        async fn set_kv_slice<'a>(&'a mut self, key: &'a str, val: &'a [u8]) -> Result<(), Error> {
            (**self).set_kv_slice(key, val).await
        }

        async fn get_kv_slice<'a, 'b>(
            &'a self,
            key: &'a str,
            buf: &'b mut [u8],
        ) -> Result<&'b [u8], Error> {
            (**self).get_kv_slice(key, buf).await
        }

        async fn set_kv_u64<'a>(&'a mut self, key: &'a str, val: u64) -> Result<(), Error> {
            (**self).set_kv_u64(key, val).await
        }

        async fn get_kv_u64<'a>(&'a self, key: &'a str) -> Result<u64, Error> {
            (**self).get_kv_u64(key).await
        }

        async fn remove<'a>(&'a mut self, key: &'a str) -> Result<(), Error> {
            (**self).remove(key).await
        }
    }

    pub struct Asyncify<T>(pub T);

    impl<T> AsyncPsm for Asyncify<T>
    where
        T: Psm,
    {
        async fn set_kv_slice<'a>(&'a mut self, key: &'a str, val: &'a [u8]) -> Result<(), Error> {
            self.0.set_kv_slice(key, val)
        }

        async fn get_kv_slice<'a, 'b>(
            &'a self,
            key: &'a str,
            buf: &'b mut [u8],
        ) -> Result<&'b [u8], Error> {
            self.0.get_kv_slice(key, buf)
        }

        async fn set_kv_u64<'a>(&'a mut self, key: &'a str, val: u64) -> Result<(), Error> {
            self.0.set_kv_u64(key, val)
        }

        async fn get_kv_u64<'a>(&'a self, key: &'a str) -> Result<u64, Error> {
            self.0.get_kv_u64(key)
        }

        async fn remove<'a>(&'a mut self, key: &'a str) -> Result<(), Error> {
            self.0.remove(key)
        }
    }
}

#[cfg(feature = "std")]
pub mod std {
    use std::fs::{self, DirBuilder, File};
    use std::io::{Read, Write};

    use crate::error::Error;

    use super::Psm;

    pub struct FilePsm {}

    const PSM_DIR: &str = "/tmp/matter_psm";

    macro_rules! psm_path {
        ($key:ident) => {
            format!("{}/{}", PSM_DIR, $key)
        };
    }

    impl FilePsm {
        pub fn new() -> Result<Self, Error> {
            let result = DirBuilder::new().create(PSM_DIR);
            if let Err(e) = result {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(e.into());
                }
            }

            Ok(Self {})
        }

        pub fn set_kv_slice(&mut self, key: &str, val: &[u8]) -> Result<(), Error> {
            let mut f = File::create(psm_path!(key))?;
            f.write_all(val)?;
            Ok(())
        }

        pub fn get_kv_slice<'a>(&self, key: &str, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
            let mut f = File::open(psm_path!(key))?;
            let mut offset = 0;

            loop {
                let len = f.read(&mut buf[offset..])?;
                offset += len;

                if len == 0 {
                    break;
                }
            }

            Ok(&buf[..offset])
        }

        pub fn set_kv_u64(&mut self, key: &str, val: u64) -> Result<(), Error> {
            let mut f = File::create(psm_path!(key))?;
            f.write_all(&val.to_be_bytes())?;
            Ok(())
        }

        pub fn get_kv_u64(&self, key: &str) -> Result<u64, Error> {
            let mut f = File::open(psm_path!(key))?;
            let mut buf = [0; 8];
            f.read_exact(&mut buf)?;
            Ok(u64::from_be_bytes(buf))
        }

        pub fn remove(&self, key: &str) -> Result<(), Error> {
            fs::remove_file(psm_path!(key))?;
            Ok(())
        }
    }

    impl Psm for FilePsm {
        fn set_kv_slice(&mut self, key: &str, val: &[u8]) -> Result<(), Error> {
            FilePsm::set_kv_slice(self, key, val)
        }

        fn get_kv_slice<'a>(&self, key: &str, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
            FilePsm::get_kv_slice(self, key, buf)
        }

        fn set_kv_u64(&mut self, key: &str, val: u64) -> Result<(), Error> {
            FilePsm::set_kv_u64(self, key, val)
        }

        fn get_kv_u64(&self, key: &str) -> Result<u64, Error> {
            FilePsm::get_kv_u64(self, key)
        }

        fn remove(&mut self, key: &str) -> Result<(), Error> {
            FilePsm::remove(self, key)
        }
    }
}
