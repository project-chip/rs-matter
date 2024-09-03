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
#[cfg(feature = "std")]
pub use fileio::*;

#[cfg(feature = "std")]
pub mod fileio {
    use core::mem::MaybeUninit;

    use std::fs;
    use std::io::{Read, Write};
    use std::path::Path;

    use log::info;

    use crate::error::{Error, ErrorCode};
    use crate::utils::init::{init, Init};
    use crate::Matter;

    pub struct Psm<const N: usize = 4096> {
        buf: MaybeUninit<[u8; N]>,
    }

    impl<const N: usize> Default for Psm<N> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<const N: usize> Psm<N> {
        #[inline(always)]
        pub const fn new() -> Self {
            Self {
                buf: MaybeUninit::uninit(),
            }
        }

        pub fn init() -> impl Init<Self> {
            init!(Self {
                buf <- crate::utils::init::zeroed(),
            })
        }

        pub fn load(&mut self, dir: &Path, matter: &Matter) -> Result<(), Error> {
            fs::create_dir_all(dir)?;

            if let Some(data) = Self::load_key(dir, "acls", unsafe { self.buf.assume_init_mut() })?
            {
                matter.load_acls(data)?;
            }

            if let Some(data) =
                Self::load_key(dir, "fabrics", unsafe { self.buf.assume_init_mut() })?
            {
                matter.load_fabrics(data)?;
            }

            Ok(())
        }

        pub fn store(&mut self, dir: &Path, matter: &Matter) -> Result<(), Error> {
            if matter.is_changed() {
                fs::create_dir_all(dir)?;

                if let Some(data) = matter.store_acls(unsafe { self.buf.assume_init_mut() })? {
                    Self::store_key(dir, "acls", data)?;
                }

                if let Some(data) = matter.store_fabrics(unsafe { self.buf.assume_init_mut() })? {
                    Self::store_key(dir, "fabrics", data)?;
                }
            }

            Ok(())
        }

        pub async fn run<P: AsRef<Path>>(
            &mut self,
            dir: P,
            matter: &Matter<'_>,
        ) -> Result<(), Error> {
            let dir = dir.as_ref();

            self.load(dir, matter)?;

            loop {
                matter.wait_changed().await;

                self.store(dir, matter)?;
            }
        }

        fn load_key<'b>(
            dir: &Path,
            key: &str,
            buf: &'b mut [u8],
        ) -> Result<Option<&'b [u8]>, Error> {
            let path = dir.join(key);

            match fs::File::open(path) {
                Ok(mut file) => {
                    let mut offset = 0;

                    loop {
                        if offset == buf.len() {
                            Err(ErrorCode::NoSpace)?;
                        }

                        let len = file.read(&mut buf[offset..])?;

                        if len == 0 {
                            break;
                        }

                        offset += len;
                    }

                    let data = &buf[..offset];

                    info!("Key {}: loaded {} bytes {:?}", key, data.len(), data);

                    Ok(Some(data))
                }
                Err(_) => Ok(None),
            }
        }

        fn store_key(dir: &Path, key: &str, data: &[u8]) -> Result<(), Error> {
            let path = dir.join(key);

            let mut file = fs::File::create(path)?;

            file.write_all(data)?;

            info!("Key {}: stored {} bytes {:?}", key, data.len(), data);

            Ok(())
        }
    }
}
