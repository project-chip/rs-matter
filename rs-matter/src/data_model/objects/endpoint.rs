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

use core::fmt;

use super::{Cluster, DeviceType, EndptId};

#[derive(Debug, Clone)]
pub struct Endpoint<'a> {
    pub id: EndptId,
    pub device_types: &'a [DeviceType],
    pub clusters: &'a [Cluster<'a>],
}

impl<'a> Endpoint<'a> {
    pub const fn new(
        id: EndptId,
        device_types: &'a [DeviceType],
        clusters: &'a [Cluster<'a>],
    ) -> Self {
        Self {
            id,
            device_types,
            clusters,
        }
    }
}

impl core::fmt::Display for Endpoint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "clusters:[")?;
        let mut comma = "";
        for cluster in self.clusters {
            write!(f, "{} {{ {} }}", comma, cluster)?;
            comma = ", ";
        }

        write!(f, "]")
    }
}
