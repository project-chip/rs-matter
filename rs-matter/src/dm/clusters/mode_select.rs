/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! ModeSelect cluster handler (Matter Application Cluster spec).
//!
//! ModeSelect (`0x0050`) lets a client pick one of a list of predefined
//! options — the spec's examples are the light pattern of a disco ball, the
//! mode of a massage chair, the wash cycle of a laundry machine.
//!
//! # ModeSelect or a Mode Base derived cluster?
//!
//! [`super::mode`] covers the same ground for appliance functions the spec
//! has standardized. The difference that decides between them is where the
//! *purpose* of the instance lives:
//!
//! - A Mode Base derived cluster carries its purpose in its **cluster ID**.
//!   A controller that sees `0x0054` knows it is looking at a robot vacuum's
//!   run mode and can build a real affordance for it — but you cannot invent
//!   a cluster ID for a purpose the spec has not defined.
//! - ModeSelect carries its purpose in a **[`Description`] string** read at
//!   runtime, plus semantic tags in a namespace you choose. A controller can
//!   show it to a user but cannot reason about it. In exchange, the purpose
//!   is yours to define.
//!
//! So: reach for a Mode Base derived cluster when one matches what you are
//! selecting, and for ModeSelect when none does — a vendor-defined
//! configuration choice, for instance. ModeSelect is not deprecated, and it
//! keeps two things Mode Base derivations dropped: writable `StartUpMode` and
//! `OnMode`, the latter coupling the selection to the endpoint's OnOff state.
//!
//! Note that an endpoint hosts at most one instance of a given cluster ID, so
//! two independent ModeSelect choices need two endpoints — which is what the
//! Mode Select device type (`0x0027`) is for. The spec's own example is a
//! coffee machine with one instance described `Milk` and another `Sugar`.
//!
//! [`Description`]: ModeSelectHooks::description
//!
//! # Usage
//!
//! ```ignore
//! use rs_matter::dm::clusters::mode_select::{
//!     ModeSelectHandler, ModeSelectHooks, Mode, SemanticTag, CLUSTER,
//! };
//!
//! const MY_VENDOR: u16 = 0xFFF1;
//!
//! const DETACHED: u16 = 0x0000;
//! const HARDWIRED: u16 = 0x0001;
//!
//! const MODES: &[Mode] = &[
//!     Mode::new(0, "Detached", &[SemanticTag::new(MY_VENDOR, DETACHED)]),
//!     Mode::new(1, "Hardwired", &[SemanticTag::new(MY_VENDOR, HARDWIRED)]),
//! ];
//!
//! struct SwitchWiring { /* ... */ }
//!
//! impl ModeSelectHooks for SwitchWiring {
//!     const CLUSTER: Cluster<'static> = CLUSTER;
//!
//!     fn description(&self) -> &str { "Switch Wiring" }
//!     fn supported_modes(&self) -> &[Mode<'_>] { MODES }
//!     fn current_mode(&self) -> ModeId { /* read persisted value */ }
//!
//!     fn change_to_mode(&self, mode: ModeId) -> Result<(), Error> {
//!         self.rewire(mode);
//!         self.store_mode(mode); // CurrentMode is non-volatile
//!         Ok(())
//!     }
//! }
//!
//! let handler = ModeSelectHandler::new(Dataver::new_rand(rand), SwitchWiring::new());
//!
//! let device_handler = EmptyHandler.chain(
//!     EpClMatcher::new(Some(1), Some(CLUSTER.id)),
//!     handler.adapt(),
//! );
//! ```

use crate::dm::types::EndptId;
use crate::dm::{
    ArrayAttributeRead, AttrChangeNotifier, AttrId, Cluster, ClusterId, Dataver, HandlerContext,
    InvokeContext, LifecycleOp, ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{Nullable, TLVBuilderParent, Utf8StrBuilder};
use crate::with;

pub use crate::dm::clusters::decl::mode_select::*;

/// Cluster metadata exposing the mandatory attributes and commands.
///
/// `StartUpMode` and `OnMode` are optional and therefore *not* included.
/// Start from `FULL_CLUSTER` when you want them:
///
/// ```ignore
/// const CLUSTER: Cluster<'static> = mode_select::FULL_CLUSTER
///     .with_features(Feature::ON_OFF.bits())
///     .with_attrs(with!(
///         required;
///         mode_select::AttributeId::StartUpMode | mode_select::AttributeId::OnMode
///     ));
/// ```
pub const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

/// The type of a mode's identifier.
///
/// This is the `Mode` field of a [`Mode`] entry, carried by `CurrentMode` and
/// by `ChangeToMode`'s `NewMode` field. It identifies a mode; it is *not* an
/// index into [`ModeSelectHooks::supported_modes`].
pub type ModeId = u8;

/// The largest `Label` and `Description` length, in bytes.
pub const MAX_LABEL_LEN: usize = 64;

/// The largest number of semantic tags a single [`Mode`] may carry.
pub const MAX_SEMANTIC_TAGS: usize = 64;

/// A semantic tag attached to a [`Mode`].
///
/// Unlike the Mode Base `ModeTagStruct`, both fields are mandatory here:
/// every tag names the vendor whose namespace `value` belongs to. Which of
/// those namespaces counts as *standard* is what the `StandardNamespace`
/// attribute selects (see [`ModeSelectHooks::standard_namespace`]); a null
/// `StandardNamespace` means the instance publishes manufacturer specific
/// tags only, which is the usual case for a vendor-defined purpose.
///
/// Tags are optional in the sense that an option may carry none — such a
/// mode is *anonymous*, and a client can only go by its `Label`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SemanticTag {
    /// The vendor ID whose namespace defines `value`.
    pub mfg_code: u16,
    /// The tag value, within that namespace.
    pub value: u16,
}

impl SemanticTag {
    /// Construct a semantic tag in `mfg_code`'s namespace.
    pub const fn new(mfg_code: u16, value: u16) -> Self {
        Self { mfg_code, value }
    }
}

/// One entry of the `SupportedModes` attribute.
///
/// The mode table is fixed for the lifetime of the firmware
/// (`SupportedModes` carries the `F` quality), so this borrows its strings
/// and tags rather than owning them.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Mode<'a> {
    /// The identifier by which this mode is selected.
    pub id: ModeId,
    /// Human-readable description of the mode. The spec constrains this to
    /// [`MAX_LABEL_LEN`]; supplying a longer one is the application's
    /// problem, not something this handler polices.
    pub label: &'a str,
    /// The machine-readable meaning of the mode, if any. May be empty: a
    /// mode with no tags is *anonymous*, and a client can only go by its
    /// `Label`. (Mode Base, by contrast, requires at least one standard tag.)
    pub tags: &'a [SemanticTag],
}

impl<'a> Mode<'a> {
    /// Construct a mode table entry.
    pub const fn new(id: ModeId, label: &'a str, tags: &'a [SemanticTag]) -> Self {
        Self { id, label, tags }
    }
}

/// Device-specific logic behind the ModeSelect cluster.
pub trait ModeSelectHooks {
    /// The cluster metadata this handler exposes. See [`CLUSTER`].
    const CLUSTER: Cluster<'static>;

    /// What this instance selects, in readable text, at most
    /// [`MAX_LABEL_LEN`] bytes — `"Milk"`, `"Sugar"`, `"Switch Wiring"`.
    ///
    /// This is the only thing that tells a client what the instance is for,
    /// so it should be specific enough to disambiguate it from any sibling
    /// ModeSelect instance on the node.
    fn description(&self) -> &str;

    /// The standard namespace the instance's standard semantic tags come
    /// from, if any.
    ///
    /// The default is null: no standard namespace, and therefore only
    /// manufacturer specific tags — the right answer for a vendor-defined
    /// purpose.
    fn standard_namespace(&self) -> Nullable<u16> {
        Nullable::none()
    }

    /// The mode table, published as `SupportedModes`.
    ///
    /// Fixed for the lifetime of the firmware, and validated once at startup
    /// (see [`ModeSelectHandler`] for what is checked).
    fn supported_modes(&self) -> &[Mode<'_>];

    /// The currently selected mode, published as `CurrentMode`.
    ///
    /// `CurrentMode` is non-volatile, so this must survive a reboot.
    fn current_mode(&self) -> ModeId;

    /// The `StartUpMode` attribute, if the cluster metadata exposes it.
    ///
    /// Non-volatile.
    fn start_up_mode(&self) -> Nullable<ModeId> {
        Nullable::none()
    }

    /// Store and persist `StartUpMode`.
    ///
    /// The handler has already checked that a non-null value names a
    /// supported mode.
    fn set_start_up_mode(&self, value: Nullable<ModeId>) -> Result<(), Error> {
        let _ = value;

        Err(ErrorCode::AttributeNotFound.into())
    }

    /// The `OnMode` attribute, if the cluster metadata exposes it.
    ///
    /// Non-volatile.
    fn on_mode(&self) -> Nullable<ModeId> {
        Nullable::none()
    }

    /// Store and persist `OnMode`.
    ///
    /// The handler has already checked that a non-null value names a
    /// supported mode.
    fn set_on_mode(&self, value: Nullable<ModeId>) -> Result<(), Error> {
        let _ = value;

        Err(ErrorCode::AttributeNotFound.into())
    }

    /// Switch the device to `mode` and remember the choice.
    ///
    /// Only called for a `mode` that is present in [`Self::supported_modes`]
    /// and differs from [`Self::current_mode`].
    ///
    /// On `Ok(())` the handler notifies subscribers, so [`Self::current_mode`]
    /// must from then on return `mode`. `CurrentMode` is non-volatile, so
    /// persist it here too.
    ///
    /// Unlike its Mode Base counterpart this cannot report *why* it failed:
    /// ModeSelect's `ChangeToMode` has no response command, only a status.
    /// Returning an error surfaces that status to the client and leaves
    /// `CurrentMode` untouched.
    fn change_to_mode(&self, mode: ModeId) -> Result<(), Error>;
}

impl<T> ModeSelectHooks for &T
where
    T: ModeSelectHooks,
{
    const CLUSTER: Cluster<'static> = T::CLUSTER;

    fn description(&self) -> &str {
        (*self).description()
    }

    fn standard_namespace(&self) -> Nullable<u16> {
        (*self).standard_namespace()
    }

    fn supported_modes(&self) -> &[Mode<'_>] {
        (*self).supported_modes()
    }

    fn current_mode(&self) -> ModeId {
        (*self).current_mode()
    }

    fn start_up_mode(&self) -> Nullable<ModeId> {
        (*self).start_up_mode()
    }

    fn set_start_up_mode(&self, value: Nullable<ModeId>) -> Result<(), Error> {
        (*self).set_start_up_mode(value)
    }

    fn on_mode(&self) -> Nullable<ModeId> {
        (*self).on_mode()
    }

    fn set_on_mode(&self, value: Nullable<ModeId>) -> Result<(), Error> {
        (*self).set_on_mode(value)
    }

    fn change_to_mode(&self, mode: ModeId) -> Result<(), Error> {
        (*self).change_to_mode(mode)
    }
}

/// Applies `OnMode` when the endpoint's OnOff cluster turns on.
///
/// This is the `ON_OFF` feature (`DEPONOFF`): when an endpoint hosts both
/// OnOff and ModeSelect and `OnMode` is not null, an OFF -> ON transition
/// sets `CurrentMode` to `OnMode` — a power-on default, e.g. a coffee machine
/// whose "Sugar" instance returns to `Medium` every time it is switched on.
/// The other three OnOff transitions leave `CurrentMode` alone.
///
/// Implemented by [`ModeSelectHandler`]; hand it to the OnOff handler on the
/// same endpoint with
/// [`OnOffHandler::with_on_mode_applier`](crate::dm::clusters::app::on_off::OnOffHandler::with_on_mode_applier).
pub trait OnModeApplier {
    /// Apply `OnMode`, if any.
    ///
    /// Returns the `(cluster, attribute)` the caller must report when the mode
    /// actually moved, and `None` when `OnMode` is null, already selected, or
    /// the device refused. Returning the path rather than taking a notifier
    /// keeps this object-safe and keeps OnOff from having to know ModeSelect's
    /// cluster and attribute IDs.
    fn apply_on_mode(&self) -> Option<(ClusterId, AttrId)>;
}

impl<T> OnModeApplier for &T
where
    T: OnModeApplier + ?Sized,
{
    fn apply_on_mode(&self) -> Option<(ClusterId, AttrId)> {
        (*self).apply_on_mode()
    }
}

/// The handler for the ModeSelect Matter cluster.
///
/// One instance serves one endpoint. Adapt it to the generic `rs-matter`
/// handler trait with [`ModeSelectHandler::adapt`].
///
/// # Startup validation
///
/// At [`LifecycleOp::Startup`] the handler checks the mode table against the
/// constraints the spec places on `SupportedModes`, and **panics** on a
/// violation — these are firmware bugs rather than anything a device can
/// recover from:
///
/// - at most 255 entries,
/// - `Mode` values unique across entries,
/// - the cluster metadata actually exposes the mandatory attributes,
/// - `OnMode` exposed if and only if the `ON_OFF` feature is set.
///
/// It then applies `StartUpMode`, and repairs a persisted `CurrentMode` that
/// is no longer in the table — which is what a firmware update that drops a
/// mode leaves behind, not a bug — to the first entry.
pub struct ModeSelectHandler<H> {
    dataver: Dataver,
    hooks: H,
}

impl<H> ModeSelectHandler<H>
where
    H: ModeSelectHooks,
{
    /// Create a handler serving ModeSelect.
    ///
    /// The endpoint is not a constructor argument: everything this handler
    /// reports on its own behalf is reported against the operation it is
    /// serving, which already carries the path. The two entry points the
    /// application calls from outside an operation - [`Self::apply_mode`] -
    /// takes it as an argument instead.
    pub const fn new(dataver: Dataver, hooks: H) -> Self {
        Self { dataver, hooks }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    /// The application's hooks.
    pub fn hooks(&self) -> &H {
        &self.hooks
    }

    /// The currently selected mode.
    pub fn current_mode(&self) -> ModeId {
        self.hooks.current_mode()
    }

    /// Whether `mode` is present in the mode table.
    pub fn is_supported_mode(&self, mode: ModeId) -> bool {
        self.hooks
            .supported_modes()
            .iter()
            .any(|option| option.id == mode)
    }

    /// Serve a read of `SupportedModes`.
    fn read_supported_modes<P>(
        &self,
        builder: ArrayAttributeRead<ModeOptionStructArrayBuilder<P>, ModeOptionStructBuilder<P>>,
    ) -> Result<P, Error>
    where
        P: TLVBuilderParent,
    {
        let modes = self.hooks.supported_modes();

        match builder {
            ArrayAttributeRead::ReadAll(mut array) => {
                for option in modes {
                    array = Self::write_option(array.push()?, option)?;
                }

                array.end()
            }
            ArrayAttributeRead::ReadOne(index, item) => {
                let Some(option) = modes.get(index as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };

                Self::write_option(item, option)
            }
            ArrayAttributeRead::ReadNone(array) => array.end(),
        }
    }

    /// Encode one `ModeOptionStruct`.
    fn write_option<P>(builder: ModeOptionStructBuilder<P>, option: &Mode<'_>) -> Result<P, Error>
    where
        P: TLVBuilderParent,
    {
        let mut tags = builder
            .label(option.label)?
            .mode(option.id)?
            .semantic_tags()?;

        for tag in option.tags {
            tags = tags
                .push()?
                .mfg_code(tag.mfg_code)?
                .value(tag.value)?
                .end()?;
        }

        tags.end()?.end()
    }

    /// Switch to `mode` outside of a `ChangeToMode` command - a front panel,
    /// an internal sequence advancing on its own, a timeout - and report the
    /// new `CurrentMode` to subscribers.
    ///
    /// Runs the same checks the command path does, so an unsupported mode is
    /// refused rather than silently stored, and a no-op change costs nothing.
    ///
    /// `notifier` is anything implementing [`AttrChangeNotifier`] - the Data
    /// Model itself, or the `HandlerContext` the caller already holds.
    pub fn apply_mode(
        &self,
        mode: ModeId,
        endpoint_id: EndptId,
        notifier: impl AttrChangeNotifier,
    ) -> Result<(), Error> {
        if !self.is_supported_mode(mode) {
            return Err(ErrorCode::ConstraintError.into());
        }

        if !self.switch_to(mode)? {
            return Ok(());
        }

        notifier.notify_attr_changed(endpoint_id, H::CLUSTER.id, AttributeId::CurrentMode as _);

        Ok(())
    }

    /// Switch to `mode` if it is not already current. Returns whether the
    /// device actually moved, so callers know whether to report.
    ///
    /// Shared by `ChangeToMode`, `StartUpMode`, `OnMode` and
    /// [`Self::apply_mode`].
    fn switch_to(&self, mode: ModeId) -> Result<bool, Error> {
        if mode == self.hooks.current_mode() {
            return Ok(false);
        }

        self.hooks.change_to_mode(mode)?;

        Ok(true)
    }

    /// Validate a write to `StartUpMode` or `OnMode`.
    ///
    /// Both must name a supported mode when not null.
    fn check_writable_mode(&self, value: &Nullable<ModeId>) -> Result<(), Error> {
        match value.as_opt_ref() {
            Some(mode) if !self.is_supported_mode(*mode) => Err(ErrorCode::ConstraintError.into()),
            _ => Ok(()),
        }
    }

    /// Apply `StartUpMode` at boot.
    ///
    /// When `StartUpMode` is not null, `CurrentMode` is set to it on power up.
    ///
    /// Note that the spec exempts reboots caused by an OTA update, after
    /// which `CurrentMode` should keep its pre-update value. rs-matter has no
    /// boot-reason plumbing yet, so that exemption is not applied here.
    fn apply_start_up_mode(&self) {
        let Some(mode) = self.hooks.start_up_mode().into_option() else {
            return;
        };

        if !self.is_supported_mode(mode) {
            error!("ModeSelect: StartUpMode {} is not in SupportedModes", mode);
            return;
        }

        if let Err(e) = self.switch_to(mode) {
            error!("ModeSelect: could not apply StartUpMode {}: {}", mode, e);
        }
    }

    /// Bring a persisted `CurrentMode` that is no longer in the mode table
    /// back to a valid value, by asking the device to move to the first entry.
    fn repair_current_mode(&self) {
        if self.is_supported_mode(self.hooks.current_mode()) {
            return;
        }

        let Some(fallback) = self.hooks.supported_modes().first().map(|o| o.id) else {
            return;
        };

        warn!(
            "ModeSelect: persisted CurrentMode {} is not in SupportedModes; switching to {}",
            self.hooks.current_mode(),
            fallback
        );

        if let Err(e) = self.switch_to(fallback) {
            error!("ModeSelect: could not switch to {}: {}", fallback, e);
        }
    }

    /// Check the handler configuration and the mode table.
    ///
    /// # Panics
    /// Panics with a describing message if the handler is misconfigured.
    fn validate(&self) {
        for id in [
            AttributeId::Description,
            AttributeId::StandardNamespace,
            AttributeId::SupportedModes,
            AttributeId::CurrentMode,
        ] {
            if H::CLUSTER.attribute(id as _).is_none() {
                panic!(
                    "ModeSelect validation: missing required attribute: {:?}",
                    id
                );
            }
        }

        // `OnMode` is what the `ON_OFF` feature adds, and the only thing it
        // adds - the two travel together in both directions.
        let on_off_feature = H::CLUSTER.feature_map & Feature::ON_OFF.bits() != 0;
        let on_mode_attr = H::CLUSTER.attribute(AttributeId::OnMode as _).is_some();

        if on_off_feature && !on_mode_attr {
            panic!(
                "ModeSelect validation: missing attribute required by the ON_OFF feature: OnMode"
            );
        }

        if !on_off_feature && on_mode_attr {
            panic!("ModeSelect validation: the OnMode attribute requires the ON_OFF feature");
        }

        let modes = self.hooks.supported_modes();

        if modes.len() > 255 {
            panic!(
                "ModeSelect validation: SupportedModes must have at most 255 entries, got {}",
                modes.len()
            );
        }

        for (index, option) in modes.iter().enumerate() {
            for (other_index, other) in modes.iter().enumerate().skip(index + 1) {
                if other.id == option.id {
                    panic!(
                        "ModeSelect validation: SupportedModes[{}] and [{}] share the Mode value {}",
                        index, other_index, option.id
                    );
                }
            }
        }
    }
}

impl<H> OnModeApplier for ModeSelectHandler<H>
where
    H: ModeSelectHooks,
{
    fn apply_on_mode(&self) -> Option<(ClusterId, AttrId)> {
        let mode = self.hooks.on_mode().into_option()?;

        match self.switch_to(mode) {
            Ok(true) => Some((H::CLUSTER.id, AttributeId::CurrentMode as _)),
            Ok(false) => None,
            Err(e) => {
                error!("ModeSelect: could not apply OnMode {}: {}", mode, e);
                None
            }
        }
    }
}

impl<H> ClusterHandler for ModeSelectHandler<H>
where
    H: ModeSelectHooks,
{
    const CLUSTER: Cluster<'static> = H::CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn lifecycle(&self, _ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        if matches!(op, LifecycleOp::Startup) {
            self.validate();
            self.repair_current_mode();
            self.apply_start_up_mode();
        }

        Ok(())
    }

    fn description<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(self.hooks.description())
    }

    fn standard_namespace(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        Ok(self.hooks.standard_namespace())
    }

    fn supported_modes<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<ModeOptionStructArrayBuilder<P>, ModeOptionStructBuilder<P>>,
    ) -> Result<P, Error> {
        self.read_supported_modes(builder)
    }

    fn current_mode(&self, _ctx: impl ReadContext) -> Result<ModeId, Error> {
        Ok(self.hooks.current_mode())
    }

    fn start_up_mode(&self, _ctx: impl ReadContext) -> Result<Nullable<ModeId>, Error> {
        Ok(self.hooks.start_up_mode())
    }

    fn set_start_up_mode(
        &self,
        ctx: impl WriteContext,
        value: Nullable<ModeId>,
    ) -> Result<(), Error> {
        self.check_writable_mode(&value)?;
        self.hooks.set_start_up_mode(value)?;
        ctx.notify_changed();

        Ok(())
    }

    fn on_mode(&self, _ctx: impl ReadContext) -> Result<Nullable<ModeId>, Error> {
        Ok(self.hooks.on_mode())
    }

    fn set_on_mode(&self, ctx: impl WriteContext, value: Nullable<ModeId>) -> Result<(), Error> {
        self.check_writable_mode(&value)?;
        self.hooks.set_on_mode(value)?;
        ctx.notify_changed();

        Ok(())
    }

    fn handle_change_to_mode(
        &self,
        ctx: impl InvokeContext,
        request: ChangeToModeRequest<'_>,
    ) -> Result<(), Error> {
        let new_mode = request.new_mode()?;

        // ModeSelect has no response command to carry a reason, so an
        // unsupported mode is simply an invalid command.
        if !self.is_supported_mode(new_mode) {
            return Err(ErrorCode::InvalidCommand.into());
        }

        if new_mode == self.hooks.current_mode() {
            return Ok(());
        }

        self.switch_to(new_mode)?;
        ctx.notify_own_attr_changed(AttributeId::CurrentMode as _);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the parts of [`ModeSelectHandler`] that need no `Matter`
    //! / operation-context setup: the startup validation rules, the
    //! `StartUpMode` / `OnMode` write guard, and `CurrentMode` repair.
    //!
    //! These branches are reachable only by misconfiguring the handler, so the
    //! CHIP integration tests never touch them - a correct DUT is exactly the
    //! one that does not trip them.

    use core::cell::Cell;

    use crate::dm::Dataver;
    use crate::with;

    use super::*;

    const TEST_VENDOR: u16 = 0xFFF1;

    const GOOD: &[Mode] = &[
        Mode::new(0, "Steady", &[SemanticTag::new(TEST_VENDOR, 0x8000)]),
        Mode::new(4, "Blink", &[SemanticTag::new(TEST_VENDOR, 0x8001)]),
    ];

    /// The full configuration: `ON_OFF` plus both optional attributes.
    const FULL: Cluster<'static> = FULL_CLUSTER
        .with_features(Feature::ON_OFF.bits())
        .with_attrs(with!(
            required;
            AttributeId::StartUpMode | AttributeId::OnMode
        ));

    struct TestHooks<'a> {
        modes: &'a [Mode<'a>],
        current: Cell<ModeId>,
    }

    impl<'a> TestHooks<'a> {
        fn new(modes: &'a [Mode<'a>], current: ModeId) -> Self {
            Self {
                modes,
                current: Cell::new(current),
            }
        }
    }

    impl ModeSelectHooks for TestHooks<'_> {
        const CLUSTER: Cluster<'static> = FULL;

        fn description(&self) -> &str {
            "Test"
        }

        fn supported_modes(&self) -> &[Mode<'_>] {
            self.modes
        }

        fn current_mode(&self) -> ModeId {
            self.current.get()
        }

        fn change_to_mode(&self, mode: ModeId) -> Result<(), Error> {
            self.current.set(mode);

            Ok(())
        }
    }

    fn handler<'a>(modes: &'a [Mode<'a>], current: ModeId) -> ModeSelectHandler<TestHooks<'a>> {
        ModeSelectHandler::new(Dataver::new(0), TestHooks::new(modes, current))
    }

    /// A hooks type that exists only to carry a deliberately broken `CLUSTER`.
    macro_rules! misconfigured {
        ($name:ident, $cluster:expr) => {
            struct $name;

            impl ModeSelectHooks for $name {
                const CLUSTER: Cluster<'static> = $cluster;

                fn description(&self) -> &str {
                    "Test"
                }

                fn supported_modes(&self) -> &[Mode<'_>] {
                    GOOD
                }

                fn current_mode(&self) -> ModeId {
                    0
                }

                fn change_to_mode(&self, _mode: ModeId) -> Result<(), Error> {
                    Ok(())
                }
            }
        };
    }

    #[test]
    fn a_spec_compliant_table_validates() {
        handler(GOOD, 0).validate();
    }

    #[test]
    #[should_panic(expected = "share the Mode value")]
    fn duplicate_mode_values_are_rejected() {
        const MODES: &[Mode] = &[
            Mode::new(0, "Steady", &[SemanticTag::new(TEST_VENDOR, 0x8000)]),
            Mode::new(0, "Blink", &[SemanticTag::new(TEST_VENDOR, 0x8001)]),
        ];

        handler(MODES, 0).validate();
    }

    #[test]
    fn an_anonymous_mode_is_allowed() {
        // Unlike Mode Base, ModeSelect permits a mode with no tags at all - a
        // client then has only the `Label` to go on.
        const MODES: &[Mode] = &[
            Mode::new(0, "Steady", &[]),
            Mode::new(4, "Blink", &[SemanticTag::new(TEST_VENDOR, 0x8001)]),
        ];

        handler(MODES, 0).validate();
    }

    #[test]
    #[should_panic(expected = "missing required attribute")]
    fn a_missing_mandatory_attribute_is_rejected() {
        misconfigured!(NoAttrs, FULL_CLUSTER.with_attrs(with!()));

        ModeSelectHandler::new(Dataver::new(0), NoAttrs).validate();
    }

    #[test]
    #[should_panic(expected = "required by the ON_OFF feature: OnMode")]
    fn the_on_off_feature_without_the_on_mode_attribute_is_rejected() {
        // `with!(required)` omits `OnMode`, which is optional.
        misconfigured!(
            FeatureNoAttr,
            FULL_CLUSTER
                .with_features(Feature::ON_OFF.bits())
                .with_attrs(with!(required))
        );

        ModeSelectHandler::new(Dataver::new(0), FeatureNoAttr).validate();
    }

    #[test]
    #[should_panic(expected = "OnMode attribute requires the ON_OFF feature")]
    fn the_on_mode_attribute_without_the_on_off_feature_is_rejected() {
        misconfigured!(
            AttrNoFeature,
            FULL_CLUSTER.with_attrs(with!(required; AttributeId::OnMode))
        );

        ModeSelectHandler::new(Dataver::new(0), AttrNoFeature).validate();
    }

    #[test]
    fn writable_modes_must_name_a_supported_mode() {
        let handler = handler(GOOD, 0);

        // Null clears the attribute and is always allowed.
        assert!(handler.check_writable_mode(&Nullable::none()).is_ok());
        assert!(handler.check_writable_mode(&Nullable::some(4)).is_ok());

        let err = handler.check_writable_mode(&Nullable::some(5)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConstraintError);
    }

    #[test]
    fn a_dropped_current_mode_falls_back_to_the_first_entry() {
        // What a firmware update that removes a mode leaves behind. Not a bug,
        // so it is repaired rather than fatal.
        let handler = handler(GOOD, 7);

        handler.repair_current_mode();

        assert_eq!(handler.current_mode(), 0);
    }

    #[test]
    fn a_valid_current_mode_is_left_alone() {
        let handler = handler(GOOD, 4);

        handler.repair_current_mode();

        assert_eq!(handler.current_mode(), 4);
    }
}
