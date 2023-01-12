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

use crate::{
    data_model::objects::{ClusterType, Endpoint},
    error::*,
    interaction_model::{core::IMStatusCode, messages::GenericPath},
    // TODO: This layer shouldn't really depend on the TLV layer, should create an abstraction layer
};
use std::fmt;

pub trait ChangeConsumer {
    fn endpoint_added(&self, id: u16, endpoint: &mut Endpoint) -> Result<(), Error>;
}

pub const ENDPTS_PER_ACC: usize = 3;

pub type BoxedEndpoints = [Option<Box<Endpoint>>];

#[derive(Default)]
pub struct Node {
    endpoints: [Option<Box<Endpoint>>; ENDPTS_PER_ACC],
    changes_cb: Option<Box<dyn ChangeConsumer>>,
}

impl std::fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "node:")?;
        for (i, element) in self.endpoints.iter().enumerate() {
            if let Some(e) = element {
                writeln!(f, "endpoint {}: {}", i, e)?;
            }
        }
        write!(f, "")
    }
}

impl Node {
    pub fn new() -> Result<Box<Node>, Error> {
        let node = Box::default();
        Ok(node)
    }

    pub fn set_changes_cb(&mut self, consumer: Box<dyn ChangeConsumer>) {
        self.changes_cb = Some(consumer);
    }

    pub fn add_endpoint(&mut self) -> Result<u32, Error> {
        let index = self
            .endpoints
            .iter()
            .position(|x| x.is_none())
            .ok_or(Error::NoSpace)?;
        let mut endpoint = Endpoint::new()?;
        if let Some(cb) = &self.changes_cb {
            cb.endpoint_added(index as u16, &mut endpoint)?;
        }
        self.endpoints[index] = Some(endpoint);
        Ok(index as u32)
    }

    pub fn get_endpoint(&self, endpoint_id: u16) -> Result<&Endpoint, Error> {
        if (endpoint_id as usize) < ENDPTS_PER_ACC {
            let endpoint = self.endpoints[endpoint_id as usize]
                .as_ref()
                .ok_or(Error::EndpointNotFound)?;
            Ok(endpoint)
        } else {
            Err(Error::EndpointNotFound)
        }
    }

    pub fn get_endpoint_mut(&mut self, endpoint_id: u16) -> Result<&mut Endpoint, Error> {
        if (endpoint_id as usize) < ENDPTS_PER_ACC {
            let endpoint = self.endpoints[endpoint_id as usize]
                .as_mut()
                .ok_or(Error::EndpointNotFound)?;
            Ok(endpoint)
        } else {
            Err(Error::EndpointNotFound)
        }
    }

    pub fn get_cluster_mut(&mut self, e: u16, c: u32) -> Result<&mut dyn ClusterType, Error> {
        self.get_endpoint_mut(e)?.get_cluster_mut(c)
    }

    pub fn get_cluster(&self, e: u16, c: u32) -> Result<&dyn ClusterType, Error> {
        self.get_endpoint(e)?.get_cluster(c)
    }

    pub fn add_cluster(
        &mut self,
        endpoint_id: u32,
        cluster: Box<dyn ClusterType>,
    ) -> Result<(), Error> {
        let endpoint_id = endpoint_id as usize;
        if endpoint_id < ENDPTS_PER_ACC {
            self.endpoints[endpoint_id]
                .as_mut()
                .ok_or(Error::NoEndpoint)?
                .add_cluster(cluster)
        } else {
            Err(Error::Invalid)
        }
    }

    // Returns a slice of endpoints, with either a single endpoint or all (wildcard)
    pub fn get_wildcard_endpoints(
        &self,
        endpoint: Option<u16>,
    ) -> Result<(&BoxedEndpoints, usize, bool), IMStatusCode> {
        if let Some(e) = endpoint {
            let e = e as usize;
            if self.endpoints.len() <= e || self.endpoints[e].is_none() {
                Err(IMStatusCode::UnsupportedEndpoint)
            } else {
                Ok((&self.endpoints[e..e + 1], e, false))
            }
        } else {
            Ok((&self.endpoints[..], 0, true))
        }
    }

    pub fn get_wildcard_endpoints_mut(
        &mut self,
        endpoint: Option<u16>,
    ) -> Result<(&mut BoxedEndpoints, usize, bool), IMStatusCode> {
        if let Some(e) = endpoint {
            let e = e as usize;
            if self.endpoints.len() <= e || self.endpoints[e].is_none() {
                Err(IMStatusCode::UnsupportedEndpoint)
            } else {
                Ok((&mut self.endpoints[e..e + 1], e, false))
            }
        } else {
            Ok((&mut self.endpoints[..], 0, true))
        }
    }

    /// Run a closure for all endpoints as specified in the path
    ///
    /// Note that the path is a GenericPath and hence can be a wildcard path. The behaviour
    /// of this function is to only capture the successful invocations and ignore the erroneous
    /// ones. This is inline with the expected behaviour for wildcard, where it implies that
    /// 'please run this operation on this wildcard path "wherever possible"'
    ///
    /// It is expected that if the closure that you pass here returns an error it may not reach
    /// out to the caller, in case there was a wildcard path specified
    pub fn for_each_endpoint<T>(&self, path: &GenericPath, mut f: T) -> Result<(), IMStatusCode>
    where
        T: FnMut(&GenericPath, &Endpoint) -> Result<(), IMStatusCode>,
    {
        let mut current_path = *path;
        let (endpoints, mut endpoint_id, wildcard) = self.get_wildcard_endpoints(path.endpoint)?;
        for e in endpoints.iter() {
            if let Some(e) = e {
                current_path.endpoint = Some(endpoint_id as u16);
                f(&current_path, e.as_ref())
                    .or_else(|e| if !wildcard { Err(e) } else { Ok(()) })?;
            }
            endpoint_id += 1;
        }
        Ok(())
    }

    /// Run a closure for all endpoints  (mutable) as specified in the path
    ///
    /// Note that the path is a GenericPath and hence can be a wildcard path. The behaviour
    /// of this function is to only capture the successful invocations and ignore the erroneous
    /// ones. This is inline with the expected behaviour for wildcard, where it implies that
    /// 'please run this operation on this wildcard path "wherever possible"'
    ///
    /// It is expected that if the closure that you pass here returns an error it may not reach
    /// out to the caller, in case there was a wildcard path specified
    pub fn for_each_endpoint_mut<T>(
        &mut self,
        path: &GenericPath,
        mut f: T,
    ) -> Result<(), IMStatusCode>
    where
        T: FnMut(&GenericPath, &mut Endpoint) -> Result<(), IMStatusCode>,
    {
        let mut current_path = *path;
        let (endpoints, mut endpoint_id, wildcard) =
            self.get_wildcard_endpoints_mut(path.endpoint)?;
        for e in endpoints.iter_mut() {
            if let Some(e) = e {
                current_path.endpoint = Some(endpoint_id as u16);
                f(&current_path, e.as_mut())
                    .or_else(|e| if !wildcard { Err(e) } else { Ok(()) })?;
            }
            endpoint_id += 1;
        }
        Ok(())
    }

    /// Run a closure for all clusters as specified in the path
    ///
    /// Note that the path is a GenericPath and hence can be a wildcard path. The behaviour
    /// of this function is to only capture the successful invocations and ignore the erroneous
    /// ones. This is inline with the expected behaviour for wildcard, where it implies that
    /// 'please run this operation on this wildcard path "wherever possible"'
    ///
    /// It is expected that if the closure that you pass here returns an error it may not reach
    /// out to the caller, in case there was a wildcard path specified
    pub fn for_each_cluster<T>(&self, path: &GenericPath, mut f: T) -> Result<(), IMStatusCode>
    where
        T: FnMut(&GenericPath, &dyn ClusterType) -> Result<(), IMStatusCode>,
    {
        self.for_each_endpoint(path, |p, e| {
            let mut current_path = *p;
            let (clusters, wildcard) = e.get_wildcard_clusters(p.cluster)?;
            for c in clusters.iter() {
                current_path.cluster = Some(c.base().id);
                f(&current_path, c.as_ref())
                    .or_else(|e| if !wildcard { Err(e) } else { Ok(()) })?;
            }
            Ok(())
        })
    }

    /// Run a closure for all clusters (mutable) as specified in the path
    ///
    /// Note that the path is a GenericPath and hence can be a wildcard path. The behaviour
    /// of this function is to only capture the successful invocations and ignore the erroneous
    /// ones. This is inline with the expected behaviour for wildcard, where it implies that
    /// 'please run this operation on this wildcard path "wherever possible"'
    ///
    /// It is expected that if the closure that you pass here returns an error it may not reach
    /// out to the caller, in case there was a wildcard path specified
    pub fn for_each_cluster_mut<T>(
        &mut self,
        path: &GenericPath,
        mut f: T,
    ) -> Result<(), IMStatusCode>
    where
        T: FnMut(&GenericPath, &mut dyn ClusterType) -> Result<(), IMStatusCode>,
    {
        self.for_each_endpoint_mut(path, |p, e| {
            let mut current_path = *p;
            let (clusters, wildcard) = e.get_wildcard_clusters_mut(p.cluster)?;

            for c in clusters.iter_mut() {
                current_path.cluster = Some(c.base().id);
                f(&current_path, c.as_mut())
                    .or_else(|e| if !wildcard { Err(e) } else { Ok(()) })?;
            }
            Ok(())
        })
    }

    /// Run a closure for all attributes as specified in the path
    ///
    /// Note that the path is a GenericPath and hence can be a wildcard path. The behaviour
    /// of this function is to only capture the successful invocations and ignore the erroneous
    /// ones. This is inline with the expected behaviour for wildcard, where it implies that
    /// 'please run this operation on this wildcard path "wherever possible"'
    ///
    /// It is expected that if the closure that you pass here returns an error it may not reach
    /// out to the caller, in case there was a wildcard path specified
    pub fn for_each_attribute<T>(&self, path: &GenericPath, mut f: T) -> Result<(), IMStatusCode>
    where
        T: FnMut(&GenericPath, &dyn ClusterType) -> Result<(), IMStatusCode>,
    {
        self.for_each_cluster(path, |current_path, c| {
            let mut current_path = *current_path;
            let (attributes, wildcard) = c
                .base()
                .get_wildcard_attribute(path.leaf.map(|at| at as u16))?;
            for a in attributes.iter() {
                current_path.leaf = Some(a.id as u32);
                f(&current_path, c).or_else(|e| if !wildcard { Err(e) } else { Ok(()) })?;
            }
            Ok(())
        })
    }
}
