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
    use std::fs;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};

    use log::info;

    use crate::error::{Error, ErrorCode};
    use crate::Matter;

    pub struct Psm<'a> {
        matter: &'a Matter<'a>,
        dir: PathBuf,
        buf: [u8; 4096],
    }

    impl<'a> Psm<'a> {
        #[inline(always)]
        pub fn new(matter: &'a Matter<'a>, dir: PathBuf) -> Result<Self, Error> {
            fs::create_dir_all(&dir)?;

            info!("Persisting from/to {}", dir.display());

            let mut buf = [0; 4096];

            if let Some(data) = Self::load(&dir, "acls", &mut buf)? {
                matter.load_acls(data)?;
            }

            if let Some(data) = Self::load(&dir, "fabrics", &mut buf)? {
                matter.load_fabrics(data)?;
            }

            Ok(Self { matter, dir, buf })
        }

        pub async fn run(&mut self) -> Result<(), Error> {
            loop {
                self.matter.wait_changed().await;

                if self.matter.is_changed() {
                    if let Some(data) = self.matter.store_acls(&mut self.buf)? {
                        Self::store(&self.dir, "acls", data)?;
                    }

                    if let Some(data) = self.matter.store_fabrics(&mut self.buf)? {
                        Self::store(&self.dir, "fabrics", data)?;
                    }
                }
            }
        }

        fn load<'b>(dir: &Path, key: &str, buf: &'b mut [u8]) -> Result<Option<&'b [u8]>, Error> {
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

        fn store(dir: &Path, key: &str, data: &[u8]) -> Result<(), Error> {
            let path = dir.join(key);

            let mut file = fs::File::create(path)?;

            file.write_all(data)?;

            info!("Key {}: stored {} bytes {:?}", key, data.len(), data);

            Ok(())
        }
    }
}
