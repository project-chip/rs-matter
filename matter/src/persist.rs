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
pub use file_psm::*;

#[cfg(feature = "std")]
mod file_psm {
    use std::fs;
    use std::io::{Read, Write};
    use std::path::PathBuf;

    use log::info;

    use crate::error::Error;

    pub struct FilePsm {
        dir: PathBuf,
    }

    impl FilePsm {
        pub fn new(dir: PathBuf) -> Result<Self, Error> {
            fs::create_dir_all(&dir)?;

            Ok(Self { dir })
        }

        pub fn load<'a>(&self, key: &str, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
            let path = self.dir.join(key);

            match fs::File::open(path) {
                Ok(mut file) => {
                    let mut offset = 0;

                    loop {
                        if offset == buf.len() {
                            return Err(Error::NoSpace);
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

        pub fn store(&self, key: &str, data: &[u8]) -> Result<(), Error> {
            let path = self.dir.join(key);

            let mut file = fs::File::create(path)?;

            file.write_all(data)?;

            info!("Key {}: stored {} bytes {:?}", key, data.len(), data);

            Ok(())
        }
    }
}
