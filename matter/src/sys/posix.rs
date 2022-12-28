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

use std::{
    convert::TryInto,
    fs::{DirBuilder, File},
    io::{Read, Write},
    sync::{Arc, Mutex, Once},
};

use crate::error::Error;

pub const SPAKE2_ITERATION_COUNT: u32 = 2000;

// The Packet Pool that is allocated from. POSIX systems can use
// higher values unlike embedded systems
pub const MAX_PACKET_POOL_SIZE: usize = 25;

pub struct Psm {}

static mut G_PSM: Option<Arc<Mutex<Psm>>> = None;
static INIT: Once = Once::new();

const PSM_DIR: &str = "/tmp/matter_psm";

macro_rules! psm_path {
    ($key:ident) => {
        format!("{}/{}", PSM_DIR, $key)
    };
}

impl Psm {
    fn new() -> Result<Self, Error> {
        let result = DirBuilder::new().create(PSM_DIR);
        if let Err(e) = result {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(e.into());
            }
        }

        Ok(Self {})
    }

    pub fn get() -> Result<Arc<Mutex<Self>>, Error> {
        unsafe {
            INIT.call_once(|| {
                G_PSM = Some(Arc::new(Mutex::new(Psm::new().unwrap())));
            });
            Ok(G_PSM.as_ref().ok_or(Error::Invalid)?.clone())
        }
    }

    pub fn set_kv_slice(&self, key: &str, val: &[u8]) -> Result<(), Error> {
        let mut f = File::create(psm_path!(key))?;
        f.write_all(val)?;
        Ok(())
    }

    pub fn get_kv_slice(&self, key: &str, val: &mut Vec<u8>) -> Result<usize, Error> {
        let mut f = File::open(psm_path!(key))?;
        let len = f.read_to_end(val)?;
        Ok(len)
    }

    pub fn set_kv_u64(&self, key: &str, val: u64) -> Result<(), Error> {
        let mut f = File::create(psm_path!(key))?;
        f.write_all(&val.to_be_bytes())?;
        Ok(())
    }

    pub fn get_kv_u64(&self, key: &str, val: &mut u64) -> Result<(), Error> {
        let mut f = File::open(psm_path!(key))?;
        let mut vec = Vec::new();
        let _ = f.read_to_end(&mut vec)?;
        *val = u64::from_be_bytes(vec.as_slice().try_into()?);
        Ok(())
    }
}
