/// Represents a specific device type
///
/// API generally just reports standarde `code` values and their
/// `version`. `name` is a human-friendly readable value.
#[derive(Debug, Clone, PartialEq, PartialOrd, Default)]
pub struct DeviceType {
    pub name: String,
    pub code: u64,
    pub version: u64,
}

/// Contains an initialization value of an attribute.
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum DefaultAttributeValue {
    Number(u64),
    Signed(i64),
    String(String),
    Bool(bool),
}

/// How an attribute value is fetched from the server
#[derive(Debug, Clone, PartialEq, PartialOrd, Default)]
pub enum AttributeHandlingType {
    /// Stored in RAM, may be lost at reboot
    #[default]
    Ram,
    /// Cluster provides custom code to handle read/writes
    Callback,
    /// Stored in RAM and persisted in NVM
    Persist,
}

/// Describes an attribute made available on a server
///
/// Name should be looked up in the corresponding cluster definition
/// to figure out actual type/sizing and other information.
#[derive(Debug, Clone, PartialEq, PartialOrd, Default)]
pub struct AttributeInstantiation {
    pub handle_type: AttributeHandlingType,
    pub name: String,
    pub default: Option<DefaultAttributeValue>,
}

/// A cluster instantiated on a specific endpoint
///
/// Data is generally string-typed and the actual types should be
/// looked up in the cluster definition if required.
#[derive(Debug, Clone, PartialEq, PartialOrd, Default)]
pub struct ClusterInstantiation {
    pub name: String,
    pub attributes: Vec<AttributeInstantiation>,
    pub commands: Vec<String>,
    pub events: Vec<String>,
}

/// Represents and endpoint exposed by a server.
#[derive(Debug, Clone, PartialEq, PartialOrd, Default)]
pub struct Endpoint {
    pub id: u64,
    pub device_types: Vec<DeviceType>,
    pub bindings: Vec<String>,
    pub instantiations: Vec<ClusterInstantiation>,
}
