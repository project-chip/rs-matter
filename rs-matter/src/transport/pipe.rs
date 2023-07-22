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

use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};

use crate::utils::select::Notification;

use super::network::Address;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Chunk {
    pub start: usize,
    pub end: usize,
    pub addr: Address,
}

pub struct PipeData<'a> {
    pub buf: &'a mut [u8],
    pub chunk: Option<Chunk>,
}

pub struct Pipe<'a> {
    pub data: Mutex<NoopRawMutex, PipeData<'a>>,
    pub data_supplied_notification: Notification,
    pub data_consumed_notification: Notification,
}

impl<'a> Pipe<'a> {
    #[inline(always)]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            data: Mutex::new(PipeData { buf, chunk: None }),
            data_supplied_notification: Notification::new(),
            data_consumed_notification: Notification::new(),
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> (usize, Address) {
        loop {
            {
                let mut data = self.data.lock().await;

                if let Some(chunk) = data.chunk {
                    buf[..chunk.end - chunk.start]
                        .copy_from_slice(&data.buf[chunk.start..chunk.end]);
                    data.chunk = None;

                    self.data_consumed_notification.signal(());

                    return (chunk.end - chunk.start, chunk.addr);
                }
            }

            self.data_supplied_notification.wait().await
        }
    }

    pub async fn send(&self, addr: Address, buf: &[u8]) {
        loop {
            {
                let mut data = self.data.lock().await;

                if data.chunk.is_none() {
                    data.buf[..buf.len()].copy_from_slice(buf);
                    data.chunk = Some(Chunk {
                        start: 0,
                        end: buf.len(),
                        addr,
                    });

                    self.data_supplied_notification.signal(());

                    break;
                }
            }

            self.data_consumed_notification.wait().await
        }
    }
}
