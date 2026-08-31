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

//! Mode Base cluster handler (Matter Application Cluster spec).
//!
//! Mode Base is a *pseudo* cluster: it has no cluster ID of its own and can
//! never be mounted on an endpoint. It exists only to be **derived from**.
//! Each derived cluster picks up the whole of Mode Base — the
//! `SupportedModes` / `CurrentMode` attributes and the `ChangeToMode`
//! command — and contributes two things of its own:
//!
//! - **mode tags** in the derived range `0x4000..=0x7FFF`, on top of the
//!   common tags in `0x0000..=0x3FFF` that Mode Base defines — codegen folds
//!   both sets into each cluster's own `ModeTag` enum,
//! - **`ChangeToMode` status codes** in the derived range `0x40..=0x7F`, on
//!   top of the common codes in `0x00..=0x3F` (see [`CommonStatusCode`]).
//!
//! The purpose of a Mode Base instance is therefore carried by its *cluster
//! ID*, not by any runtime attribute — unlike [`super::mode_select`], which
//! keeps a `Description` string and so can serve a vendor-defined purpose.
//! Pick the derived cluster that matches your appliance function; pick
//! `ModeSelect` when the spec has no cluster for what you are selecting.
//!
//! # What this module provides
//!
//! [`ModeHandler`] implements the Mode Base logic exactly once, and a macro
//! wires it to every derived cluster the IDL generates. Each derived cluster
//! gets its own submodule here — [`rvc_run_mode`], [`dishwasher_mode`], … —
//! re-exporting that cluster's generated `ModeTag` / `StatusCode` enums
//! alongside a ready-made [`rvc_run_mode::CLUSTER`] metadata constant and an
//! `adapt` function.
//!
//! The device-specific part lives behind the [`ModeHooks`] trait: the mode
//! table, the persisted `CurrentMode`, and the decision of whether a
//! requested transition is possible right now. All of it is synchronous —
//! `ChangeToMode` asks the device to *decide*, and a transition that takes
//! real time reports its progress through the endpoint's operational-state
//! cluster rather than by delaying the response.
//!
//! # Mode changes from outside Matter
//!
//! `CurrentMode` may change at any time by other means — a front panel, an
//! internal sequence advancing on its own, a timeout. The handler runs no
//! background task of its own for this; drive it from wherever your
//! application already drives the device, via
//! [`ModeHandler::apply_mode`]:
//!
//! ```ignore
//! handler.apply_mode(new_mode, endpoint_id, notifier)?;
//! ```
//!
//! That runs the same validation the `ChangeToMode` command does and reports
//! [`ATTR_CURRENT_MODE`] to subscribers. `notifier` is anything implementing
//! [`crate::dm::AttrChangeNotifier`] — the Data Model itself, or the
//! `HandlerContext` a sibling handler is already holding.
//!
//! # Usage
//!
//! ```ignore
//! use rs_matter::dm::clusters::mode::{
//!     rvc_run_mode, ModeHandler, ModeHooks, ModeChangeError, Mode, ModeTag,
//! };
//! // Aliasing keeps the table readable: the cluster's enum and the wrapper
//! // are both called `ModeTag`.
//! use rs_matter::dm::clusters::mode::rvc_run_mode::ModeTag as RunTag;
//!
//! const MODES: &[Mode<RunTag>] = &[
//!     Mode::new(0, "Idle", &[
//!         ModeTag::Standard(RunTag::Auto),
//!         ModeTag::Standard(RunTag::Idle),
//!     ]),
//!     Mode::new(1, "Cleaning", &[
//!         ModeTag::Standard(RunTag::Cleaning),
//!     ]),
//! ];
//!
//! struct Vacuum { /* ... */ }
//!
//! impl ModeHooks for Vacuum {
//!     const CLUSTER: Cluster<'static> = rvc_run_mode::CLUSTER;
//!     type ModeTag = RunTag;
//!
//!     fn supported_modes(&self) -> &[Mode<'_, RunTag>] { MODES }
//!     fn current_mode(&self) -> ModeId { /* read persisted value */ }
//!
//!     fn change_to_mode(&self, mode: ModeId) -> Result<(), ModeChangeError> {
//!         if self.dust_bin_missing() {
//!             return Err(ModeChangeError::derived(
//!                 rvc_run_mode::StatusCode::DustBinMissing as _,
//!                 "The dust bin is missing",
//!             ));
//!         }
//!
//!         self.start_cleaning(mode);
//!         self.store_mode(mode); // CurrentMode is non-volatile
//!
//!         Ok(())
//!     }
//! }
//!
//! let handler = ModeHandler::new(Dataver::new_rand(rand), Vacuum::new());
//!
//! let device_handler = EmptyHandler.chain(
//!     EpClMatcher::new(Some(1), Some(rvc_run_mode::CLUSTER.id)),
//!     rvc_run_mode::adapt(handler),
//! );
//! ```

use crate::dm::types::EndptId;
use crate::dm::{
    ArrayAttributeRead, AttrChangeNotifier, AttrId, Cluster, Dataver, HandlerContext,
    InvokeContext, LifecycleOp,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::TLVBuilderParent;

pub use crate::dm::clusters::decl::globals::{
    ModeOptionStruct, ModeOptionStructArrayBuilder, ModeOptionStructBuilder, ModeTagStruct,
    ModeTagStructArrayBuilder, ModeTagStructBuilder,
};

/// The `SupportedModes` attribute ID, as defined by Mode Base and therefore
/// shared by every derived cluster.
pub const ATTR_SUPPORTED_MODES: AttrId = 0x0000;

/// The `CurrentMode` attribute ID, as defined by Mode Base and therefore
/// shared by every derived cluster.
pub const ATTR_CURRENT_MODE: AttrId = 0x0001;

/// The type of a mode's identifier.
///
/// This is the `Mode` field of a [`Mode`] entry, carried by `CurrentMode` and
/// by `ChangeToMode`'s `NewMode` field. It identifies a mode; it is *not* an
/// index into [`ModeHooks::supported_modes`]. The only constraint the spec
/// places across entries is that the values be distinct — they need not be
/// contiguous, ordered, or start at zero.
pub type ModeId = u8;

/// The largest number of mode tags a single [`Mode`] may carry.
pub const MAX_MODE_TAGS: usize = 8;

/// The largest `Label` length, in bytes.
pub const MAX_LABEL_LEN: usize = 64;

/// The common `ChangeToModeResponse` status codes, defined by Mode Base
/// itself and available in every derived cluster.
///
/// These occupy the `CommonCodes` range `0x00..=0x3F`. Derived clusters add
/// their own codes in `0x40..=0x7F` (reachable through each derived
/// submodule's generated `StatusCode` enum), and manufacturers add theirs in
/// `0x80..=0xBF`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum CommonStatusCode {
    /// Switching to the requested mode is allowed and possible; `CurrentMode`
    /// has been set to it.
    Success = 0x00,
    /// The requested mode does not match any entry of `SupportedModes`.
    ///
    /// Produced by [`ModeHandler`] itself — never by [`ModeHooks`], which is
    /// only consulted for modes that are known to be supported.
    UnsupportedMode = 0x01,
    /// Generic failure, used when no more specific code applies.
    GenericFailure = 0x02,
    /// The request cannot be handled given the current mode of the device.
    InvalidInMode = 0x03,
}

/// Lower/upper bounds of the `DerivedClusterCodes` status range.
const STATUS_DERIVED_MIN: u8 = 0x40;
const STATUS_DERIVED_MAX: u8 = 0x7F;
/// Lower/upper bounds of the `MfgCodes` status range.
const STATUS_MFG_MIN: u8 = 0x80;
const STATUS_MFG_MAX: u8 = 0xBF;

/// Lower/upper bounds of the `MfgTags` mode-tag range.
const TAG_MFG_MIN: u16 = 0x8000;
const TAG_MFG_MAX: u16 = 0xBFFF;

/// Bridges a derived cluster's generated `ModeTag` enum to the `enum16` it
/// encodes as.
///
/// Implemented for each derived cluster by the wiring macro; there is no
/// reason to implement it by hand.
pub trait StandardModeTag: Copy + PartialEq {
    /// The tag's wire value.
    fn value(self) -> u16;
}

/// A single mode tag attached to a [`Mode`].
///
/// A tag is either **standard** — defined by Mode Base itself or by the
/// concrete derived cluster, both of which codegen folds into that cluster's
/// own `ModeTag` enum — or **manufacturer specific**, in which case it
/// carries the defining vendor's ID. Tags are what let a controller
/// understand a mode without knowing the device: `Label` is for humans, tags
/// are for machines.
///
/// The standard variant is typed by the cluster's own enum rather than by a
/// raw `u16`, so a tag cannot be borrowed from the wrong cluster. That is not
/// hypothetical: `rvc_clean_mode::ModeTag::Mop` and
/// `rvc_run_mode::ModeTag::Mapping` are both `0x4002`, and as plain integers
/// they substitute for each other silently.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ModeTag<T> {
    /// A tag from the cluster's own namespace, common or derived.
    Standard(T),
    /// A tag from `mfg_code`'s namespace, in `0x8000..=0xBFFF`.
    Manufacturer {
        /// The vendor ID defining this tag.
        mfg_code: u16,
        /// The tag value, within that vendor's namespace.
        value: u16,
    },
}

impl<T> ModeTag<T> {
    /// A manufacturer specific tag, in the namespace of `vendor_id`.
    ///
    /// # Panics
    /// Panics if `value` is outside the manufacturer range `0x8000..=0xBFFF`.
    /// In a `const` context this is a compile-time error.
    pub const fn manufacturer(vendor_id: u16, value: u16) -> Self {
        ::core::assert!(
            value >= TAG_MFG_MIN && value <= TAG_MFG_MAX,
            "Mode tag: manufacturer specific tags must be in the range 0x8000..=0xBFFF"
        );

        Self::Manufacturer {
            mfg_code: vendor_id,
            value,
        }
    }

    /// Whether this is a standard tag. Every [`Mode`] must carry at
    /// least one.
    pub const fn is_standard(&self) -> bool {
        matches!(self, Self::Standard(_))
    }
}

impl<T> ModeTag<T>
where
    T: StandardModeTag,
{
    /// The `MfgCode` field to encode, absent for a standard tag.
    fn mfg_code(&self) -> Option<u16> {
        match self {
            Self::Standard(_) => None,
            Self::Manufacturer { mfg_code, .. } => Some(*mfg_code),
        }
    }

    /// The `Value` field to encode.
    fn value(&self) -> u16 {
        match self {
            Self::Standard(tag) => tag.value(),
            Self::Manufacturer { value, .. } => *value,
        }
    }
}

/// One entry of the `SupportedModes` attribute.
///
/// The mode table is fixed for the lifetime of the firmware (`SupportedModes`
/// carries the `F` quality), so this borrows its strings and tags rather than
/// owning them — a `&'static [Mode<'static>]` is the typical shape.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Mode<'a, T> {
    /// The identifier by which this mode is selected.
    pub id: ModeId,
    /// Human-readable description of the mode. The spec constrains this to
    /// [`MAX_LABEL_LEN`]; supplying a longer one is the application's
    /// problem, not something this handler polices.
    pub label: &'a str,
    /// The machine-readable meaning of the mode: at least one tag, at least
    /// one of which is standard. The spec caps the count at
    /// [`MAX_MODE_TAGS`].
    pub tags: &'a [ModeTag<T>],
}

impl<'a, T> Mode<'a, T> {
    /// Construct a mode table entry.
    pub const fn new(id: ModeId, label: &'a str, tags: &'a [ModeTag<T>]) -> Self {
        Self { id, label, tags }
    }
}

/// A refusal to switch modes, returned by [`ModeHooks::change_to_mode`].
///
/// Carries the `ChangeToModeResponse` `Status` and `StatusText` fields.
/// `Success` is deliberately not expressible: a hook that does not switch
/// must not be able to report that it did.
///
/// `StatusText` is mandatory for every non-`Success` status, so the
/// constructors take it by value and reject an empty one — at compile time
/// when the error is built in a `const`. It should explain *why* the
/// transition was refused, in terms a user can act on.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ModeChangeError {
    status: u8,
    text: &'static str,
}

impl ModeChangeError {
    /// Refuse with `GenericFailure`, for when no more specific code applies.
    ///
    /// # Panics
    /// Panics if `text` is empty.
    pub const fn generic(text: &'static str) -> Self {
        ::core::assert!(
            !text.is_empty(),
            "ChangeToMode status: StatusText is mandatory for a non-Success status"
        );

        Self {
            status: CommonStatusCode::GenericFailure as u8,
            text,
        }
    }

    /// Refuse with `InvalidInMode`, for when the device's current mode is
    /// what prevents the transition.
    ///
    /// # Panics
    /// Panics if `text` is empty.
    pub const fn invalid_in_mode(text: &'static str) -> Self {
        ::core::assert!(
            !text.is_empty(),
            "ChangeToMode status: StatusText is mandatory for a non-Success status"
        );

        Self {
            status: CommonStatusCode::InvalidInMode as u8,
            text,
        }
    }

    /// Refuse with a status code from the derived cluster's own namespace.
    ///
    /// Pass the derived cluster's generated `StatusCode` enum, e.g.
    /// `ModeChangeError::derived(rvc_run_mode::StatusCode::DustBinFull as _, "...")`.
    ///
    /// # Panics
    /// Panics if `status` is outside the derived range `0x40..=0x7F`, or if
    /// `text` is empty. In a `const` context this is a compile-time error.
    pub const fn derived(status: u8, text: &'static str) -> Self {
        ::core::assert!(
            status >= STATUS_DERIVED_MIN && status <= STATUS_DERIVED_MAX,
            "ChangeToMode status: derived-cluster codes must be in the range 0x40..=0x7F"
        );

        ::core::assert!(
            !text.is_empty(),
            "ChangeToMode status: StatusText is mandatory for a non-Success status"
        );

        Self { status, text }
    }

    /// Refuse with a manufacturer specific status code.
    ///
    /// # Panics
    /// Panics if `status` is outside the manufacturer range `0x80..=0xBF`,
    /// or if `text` is empty. In a `const` context this is a compile-time
    /// error.
    pub const fn manufacturer(status: u8, text: &'static str) -> Self {
        ::core::assert!(
            status >= STATUS_MFG_MIN && status <= STATUS_MFG_MAX,
            "ChangeToMode status: manufacturer specific codes must be in the range 0x80..=0xBF"
        );

        ::core::assert!(
            !text.is_empty(),
            "ChangeToMode status: StatusText is mandatory for a non-Success status"
        );

        Self { status, text }
    }

    /// The `Status` field to report.
    pub const fn status(&self) -> u8 {
        self.status
    }

    /// The `StatusText` field to report.
    pub const fn text(&self) -> &'static str {
        self.text
    }
}

/// Device-specific logic behind a Mode Base derived cluster.
///
/// The handler owns everything the spec pins down — the shape of the
/// `SupportedModes` encoding, the `ChangeToMode` decision tree, the ordering
/// between "device agreed" and "`CurrentMode` updated". What is left here is
/// what only the device knows.
pub trait ModeHooks {
    /// The cluster metadata this handler exposes.
    ///
    /// This selects *which* derived cluster the handler serves, so it must
    /// name one of the derived submodules of this module, e.g.
    /// `rvc_run_mode::CLUSTER` or `oven_mode::FULL_CLUSTER.with_attrs(...)`.
    const CLUSTER: Cluster<'static>;

    /// The derived cluster's own `ModeTag` enum, e.g.
    /// [`rvc_run_mode::ModeTag`]. Codegen folds both the common Mode Base
    /// tags and the cluster's own into it, so it is the only standard-tag
    /// vocabulary this cluster needs.
    type ModeTag: StandardModeTag;

    /// The mode table, published as `SupportedModes`.
    ///
    /// Fixed for the lifetime of the firmware, and validated once at startup
    /// (see [`ModeHandler`] for what is checked).
    fn supported_modes(&self) -> &[Mode<'_, Self::ModeTag>];

    /// The currently selected mode, published as `CurrentMode`.
    ///
    /// `CurrentMode` is non-volatile, so this must survive a reboot.
    fn current_mode(&self) -> ModeId;

    /// Switch the device to `mode` and remember the choice, or say why that
    /// is not possible right now.
    ///
    /// Only called for a `mode` that is present in [`Self::supported_modes`]
    /// and differs from [`Self::current_mode`] — the unsupported and
    /// already-in-that-mode cases are answered by the handler without
    /// reaching the device.
    ///
    /// On `Ok(())` the handler reports `Success` and notifies subscribers, so
    /// [`Self::current_mode`] must from then on return `mode`. `CurrentMode`
    /// is non-volatile, so persist it here too. On [`ModeChangeError`] the
    /// handler reports the carried status and text and nothing else changes.
    ///
    /// This is a *decision*, not the whole transition: answer whether the
    /// switch is allowed and start it. A device whose transition takes real
    /// time reports its progress through the endpoint's operational-state
    /// cluster, not by delaying this answer.
    ///
    /// The default refuses every transition. That is the correct behaviour
    /// for [`microwave_oven_mode`], the one derived cluster with no
    /// `ChangeToMode` command — its mode is driven by the Microwave Oven
    /// Control cluster instead — and every other derived cluster must
    /// override it.
    fn change_to_mode(&self, mode: ModeId) -> Result<(), ModeChangeError> {
        let _ = mode;

        Err(ModeChangeError::generic("Mode changes are not supported"))
    }
}

impl<T> ModeHooks for &T
where
    T: ModeHooks,
{
    const CLUSTER: Cluster<'static> = T::CLUSTER;

    type ModeTag = T::ModeTag;

    fn supported_modes(&self) -> &[Mode<'_, Self::ModeTag>] {
        (*self).supported_modes()
    }

    fn current_mode(&self) -> ModeId {
        (*self).current_mode()
    }

    fn change_to_mode(&self, mode: ModeId) -> Result<(), ModeChangeError> {
        (*self).change_to_mode(mode)
    }
}

/// Writes a `ChangeToModeResponse` for one derived cluster.
///
/// Each derived cluster generates its own response builder type, so the
/// shared [`ModeHandler::process_change_to_mode`] logic reaches them through
/// this trait. Implemented by the macro that wires up each derived cluster;
/// there is no reason to implement it by hand.
pub trait ChangeToModeResponseWriter<P> {
    /// Emit `Status` and `StatusText` and close the response struct.
    fn write_response(self, status: u8, text: Option<&str>) -> Result<P, Error>;
}

/// The handler for the Mode Base derived Matter clusters.
///
/// One instance serves one cluster on one endpoint. Which derived cluster
/// that is follows from [`ModeHooks::CLUSTER`]; adapt the handler to the
/// generic `rs-matter` handler trait through the matching submodule's
/// `adapt` function, e.g. [`rvc_run_mode::adapt`].
///
/// # Startup validation
///
/// At [`LifecycleOp::Startup`] the handler checks the mode table against the
/// constraints the spec places on `SupportedModes`, and **panics** on a
/// violation — these are firmware bugs that would otherwise surface as
/// certification failures rather than as anything a device can recover from:
///
/// - between 2 and 255 entries,
/// - `Mode` values unique across entries,
/// - `Label` values unique across entries,
/// - at least one tag per entry, no repeats within an entry, at least one of
///   them standard,
/// - tag sets distinct between entries,
/// - the cluster metadata actually exposes `SupportedModes` and `CurrentMode`.
///
/// A persisted `CurrentMode` that is not in the table is *not* a firmware
/// bug — it is what a firmware update that drops a mode leaves behind — so
/// the handler repairs it to the first entry rather than panicking.
pub struct ModeHandler<H> {
    dataver: Dataver,
    hooks: H,
}

impl<H> ModeHandler<H>
where
    H: ModeHooks,
{
    /// Create a handler serving the derived cluster named by
    /// [`ModeHooks::CLUSTER`].
    ///
    /// The endpoint is not a constructor argument: everything this handler
    /// reports is reported against the operation it is serving, which already
    /// carries the path.
    pub const fn new(dataver: Dataver, hooks: H) -> Self {
        Self { dataver, hooks }
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

    /// The first mode carrying `tag`, if any.
    ///
    /// Useful for driving the device from a semantic tag rather than from a
    /// mode number — "switch to whatever this cluster calls `Idle`" — which
    /// is how a mode table survives being reordered.
    pub fn mode_by_tag(&self, tag: ModeTag<H::ModeTag>) -> Option<ModeId> {
        self.hooks
            .supported_modes()
            .iter()
            .find(|option| option.tags.contains(&tag))
            .map(|option| option.id)
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
    ) -> Result<(), ModeChangeError> {
        if !self.is_supported_mode(mode) {
            return Err(ModeChangeError::generic("Mode is not in SupportedModes"));
        }

        if mode == self.hooks.current_mode() {
            return Ok(());
        }

        self.hooks.change_to_mode(mode)?;

        notifier.notify_attr_changed(endpoint_id, H::CLUSTER.id, ATTR_CURRENT_MODE);

        Ok(())
    }

    /// Serve a read of `SupportedModes`.
    pub fn read_supported_modes<P>(
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
    fn write_option<P>(
        builder: ModeOptionStructBuilder<P>,
        option: &Mode<'_, H::ModeTag>,
    ) -> Result<P, Error>
    where
        P: TLVBuilderParent,
    {
        let mut tags = builder.label(option.label)?.mode(option.id)?.mode_tags()?;

        for tag in option.tags {
            tags = tags
                .push()?
                .mfg_code(tag.mfg_code())?
                .value(tag.value())?
                .end()?;
        }

        tags.end()?.end()
    }

    /// Serve a `ChangeToMode` invocation.
    ///
    /// The three outcomes the spec distinguishes, in the order it requires
    /// them to be checked:
    ///
    /// - `NewMode` is not in `SupportedModes`: `UnsupportedMode`, with
    ///   `StatusText` present and empty.
    /// - `NewMode` is already the current mode: `Success`, without troubling
    ///   the device.
    /// - otherwise the device decides, and `CurrentMode` moves only if it
    ///   agreed.
    pub fn process_change_to_mode<P, B>(
        &self,
        ctx: impl InvokeContext,
        new_mode: ModeId,
        response: B,
    ) -> Result<P, Error>
    where
        P: TLVBuilderParent,
        B: ChangeToModeResponseWriter<P>,
    {
        if !self.is_supported_mode(new_mode) {
            // `StatusText` is mandatory for a non-`Success` status, and the
            // spec pins it to the empty string for this one specifically:
            // `UnsupportedMode` is self-explanatory.
            return response.write_response(CommonStatusCode::UnsupportedMode as u8, Some(""));
        }

        if new_mode == self.hooks.current_mode() {
            return response.write_response(CommonStatusCode::Success as u8, None);
        }

        match self.hooks.change_to_mode(new_mode) {
            Ok(()) => {
                ctx.notify_own_attr_changed(ATTR_CURRENT_MODE);

                response.write_response(CommonStatusCode::Success as u8, None)
            }
            Err(err) => response.write_response(err.status(), Some(err.text())),
        }
    }

    /// Handle a lifecycle notification.
    pub fn process_lifecycle(
        &self,
        _ctx: impl HandlerContext,
        op: LifecycleOp,
    ) -> Result<(), Error> {
        if matches!(op, LifecycleOp::Startup) {
            self.validate();
            self.repair_current_mode();
        }

        Ok(())
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
            "Mode: persisted CurrentMode {} is not in SupportedModes; switching to {}",
            self.hooks.current_mode(),
            fallback
        );

        if let Err(e) = self.hooks.change_to_mode(fallback) {
            error!(
                "Mode: could not switch to {}: status {}, {}",
                fallback,
                e.status(),
                e.text()
            );
        }
    }

    /// Check the mode table against the constraints the spec places on
    /// `SupportedModes`.
    ///
    /// # Panics
    /// Panics with a describing message if the handler is misconfigured.
    fn validate(&self) {
        if H::CLUSTER.attribute(ATTR_SUPPORTED_MODES).is_none() {
            panic!("Mode validation: missing required attribute: SupportedModes");
        }

        if H::CLUSTER.attribute(ATTR_CURRENT_MODE).is_none() {
            panic!("Mode validation: missing required attribute: CurrentMode");
        }

        let modes = self.hooks.supported_modes();

        if modes.len() < 2 {
            panic!(
                "Mode validation: SupportedModes must have at least 2 entries, got {}",
                modes.len()
            );
        }

        if modes.len() > 255 {
            panic!(
                "Mode validation: SupportedModes must have at most 255 entries, got {}",
                modes.len()
            );
        }

        for (index, option) in modes.iter().enumerate() {
            if option.tags.is_empty() {
                panic!(
                    "Mode validation: SupportedModes[{}] has no mode tags, at least 1 required",
                    index
                );
            }

            for (tag_index, tag) in option.tags.iter().enumerate() {
                if option
                    .tags
                    .iter()
                    .skip(tag_index + 1)
                    .any(|other| other == tag)
                {
                    panic!(
                        "Mode validation: SupportedModes[{}] repeats a mode tag",
                        index
                    );
                }
            }

            if !option.tags.iter().any(ModeTag::is_standard) {
                panic!(
                    "Mode validation: SupportedModes[{}] has no standard mode tag, at least 1 required",
                    index
                );
            }

            for (other_index, other) in modes.iter().enumerate().skip(index + 1) {
                if other.id == option.id {
                    panic!(
                        "Mode validation: SupportedModes[{}] and [{}] share the Mode value {}",
                        index, other_index, option.id
                    );
                }

                if other.label == option.label {
                    panic!(
                        "Mode validation: SupportedModes[{}] and [{}] share the Label {:?}",
                        index, other_index, option.label
                    );
                }

                if Self::same_tag_set(option.tags, other.tags) {
                    panic!(
                        "Mode validation: SupportedModes[{}] and [{}] have identical mode tag sets",
                        index, other_index
                    );
                }
            }
        }
    }

    /// Whether two tag lists denote the same set, disregarding order and
    /// repetition — the comparison the spec uses to require that the tag sets
    /// of two modes be distinct.
    fn same_tag_set(left: &[ModeTag<H::ModeTag>], right: &[ModeTag<H::ModeTag>]) -> bool {
        left.iter().all(|tag| right.contains(tag)) && right.iter().all(|tag| left.contains(tag))
    }
}

/// Wire [`ModeHandler`] to one IDL-generated Mode Base derived cluster.
///
/// Every derived cluster generates its own `ClusterHandler` trait, attribute
/// and command enums, request/response types and handler adaptor, none of
/// which the codegen knows are related. This emits, per cluster, a submodule
/// that re-exports the generated items — most usefully that cluster's own
/// `ModeTag` and `StatusCode` enums — alongside ready-made cluster metadata,
/// an `adapt` function, and the trait impls forwarding into the shared
/// handler.
///
/// The `read_only` form is for a derived cluster with no `ChangeToMode`
/// command.
macro_rules! derived_mode_cluster {
    ($module:ident, $doc:expr) => {
        #[doc = $doc]
        pub mod $module {
            use crate::dm::clusters::decl::globals::{
                ModeOptionStructArrayBuilder, ModeOptionStructBuilder,
            };
            use crate::dm::{
                ArrayAttributeRead, Cluster, HandlerContext, InvokeContext, LifecycleOp,
                ReadContext,
            };

            use crate::error::Error;
            use crate::tlv::TLVBuilderParent;
            use crate::with;

            use super::{
                ChangeToModeResponseWriter, ModeHandler, ModeHooks, ModeId, ATTR_CURRENT_MODE,
                ATTR_SUPPORTED_MODES,
            };

            pub use crate::dm::clusters::decl::$module::*;

            /// Cluster metadata exposing the mandatory attributes and commands.
            ///
            /// Start from `FULL_CLUSTER` instead when the cluster has optional
            /// features to opt into — `Feature::DIRECT_MODE_CHANGE`, say.
            pub const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

            /// Adapt a [`ModeHandler`] serving this cluster to the generic
            /// `rs-matter` handler trait.
            pub const fn adapt<H: ModeHooks>(
                handler: ModeHandler<H>,
            ) -> HandlerAdaptor<ModeHandler<H>> {
                HandlerAdaptor(handler)
            }

            // The shared handler notifies against Mode Base's attribute IDs,
            // so a derived cluster that renumbered them would report against
            // the wrong path. Catch that at compile time rather than in
            // certification.
            //
            // `::core::assert!` rather than the crate-wide `assert!`, which
            // maps to the non-const-evaluable `defmt::assert!` under `defmt`.
            const _: () = {
                ::core::assert!(AttributeId::SupportedModes as u32 == ATTR_SUPPORTED_MODES);
                ::core::assert!(AttributeId::CurrentMode as u32 == ATTR_CURRENT_MODE);
            };

            // Codegen folds the common Mode Base tags and this cluster's own
            // into a single `enum16`, so it is the whole standard vocabulary.
            impl super::StandardModeTag for ModeTag {
                fn value(self) -> u16 {
                    self as u16
                }
            }

            impl<P> ChangeToModeResponseWriter<P> for ChangeToModeResponseBuilder<P>
            where
                P: TLVBuilderParent,
            {
                fn write_response(self, status: u8, text: Option<&str>) -> Result<P, Error> {
                    self.status(status)?.status_text(text)?.end()
                }
            }

            impl<H> ClusterHandler for ModeHandler<H>
            where
                H: ModeHooks,
            {
                const CLUSTER: Cluster<'static> = H::CLUSTER;

                fn dataver(&self) -> u32 {
                    self.dataver.get()
                }

                fn dataver_changed(&self) {
                    self.dataver.changed();
                }

                fn lifecycle(
                    &self,
                    ctx: impl HandlerContext,
                    op: LifecycleOp,
                ) -> Result<(), Error> {
                    self.process_lifecycle(ctx, op)
                }

                fn supported_modes<P: TLVBuilderParent>(
                    &self,
                    _ctx: impl ReadContext,
                    builder: ArrayAttributeRead<
                        ModeOptionStructArrayBuilder<P>,
                        ModeOptionStructBuilder<P>,
                    >,
                ) -> Result<P, Error> {
                    self.read_supported_modes(builder)
                }

                fn current_mode(&self, _ctx: impl ReadContext) -> Result<ModeId, Error> {
                    Ok(self.hooks().current_mode())
                }

                fn handle_change_to_mode<P: TLVBuilderParent>(
                    &self,
                    ctx: impl InvokeContext,
                    request: ChangeToModeRequest<'_>,
                    response: ChangeToModeResponseBuilder<P>,
                ) -> Result<P, Error> {
                    self.process_change_to_mode(ctx, request.new_mode()?, response)
                }
            }
        }
    };

    ($module:ident, $doc:expr, read_only) => {
        #[doc = $doc]
        pub mod $module {
            use crate::dm::clusters::decl::globals::{
                ModeOptionStructArrayBuilder, ModeOptionStructBuilder,
            };
            use crate::dm::{
                ArrayAttributeRead, Cluster, HandlerContext, LifecycleOp, ReadContext,
            };
            use crate::error::Error;
            use crate::tlv::TLVBuilderParent;
            use crate::with;

            use super::{ModeHandler, ModeHooks, ModeId, ATTR_CURRENT_MODE, ATTR_SUPPORTED_MODES};

            pub use crate::dm::clusters::decl::$module::*;

            /// Cluster metadata exposing the mandatory attributes.
            pub const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

            /// Adapt a [`ModeHandler`] serving this cluster to the generic
            /// `rs-matter` handler trait.
            pub const fn adapt<H: ModeHooks>(
                handler: ModeHandler<H>,
            ) -> HandlerAdaptor<ModeHandler<H>> {
                HandlerAdaptor(handler)
            }

            const _: () = {
                ::core::assert!(AttributeId::SupportedModes as u32 == ATTR_SUPPORTED_MODES);
                ::core::assert!(AttributeId::CurrentMode as u32 == ATTR_CURRENT_MODE);
            };

            // Codegen folds the common Mode Base tags and this cluster's own
            // into a single `enum16`, so it is the whole standard vocabulary.
            impl super::StandardModeTag for ModeTag {
                fn value(self) -> u16 {
                    self as u16
                }
            }

            impl<H> ClusterHandler for ModeHandler<H>
            where
                H: ModeHooks,
            {
                const CLUSTER: Cluster<'static> = H::CLUSTER;

                fn dataver(&self) -> u32 {
                    self.dataver.get()
                }

                fn dataver_changed(&self) {
                    self.dataver.changed();
                }

                fn lifecycle(
                    &self,
                    ctx: impl HandlerContext,
                    op: LifecycleOp,
                ) -> Result<(), Error> {
                    self.process_lifecycle(ctx, op)
                }

                fn supported_modes<P: TLVBuilderParent>(
                    &self,
                    _ctx: impl ReadContext,
                    builder: ArrayAttributeRead<
                        ModeOptionStructArrayBuilder<P>,
                        ModeOptionStructBuilder<P>,
                    >,
                ) -> Result<P, Error> {
                    self.read_supported_modes(builder)
                }

                fn current_mode(&self, _ctx: impl ReadContext) -> Result<ModeId, Error> {
                    Ok(self.hooks().current_mode())
                }
            }
        }
    };
}

derived_mode_cluster!(
    oven_mode,
    "Oven Mode (`0x0049`). Adds the Bake, Convection, Grill, Roast, Clean, \
     Steam, AirFry and related mode tags."
);

derived_mode_cluster!(
    laundry_washer_mode,
    "Laundry Washer Mode (`0x0051`). Adds the Normal, Delicate, Heavy and \
     Whites mode tags; at least one mode must carry Normal."
);

derived_mode_cluster!(
    refrigerator_and_temperature_controlled_cabinet_mode,
    "Refrigerator And Temperature Controlled Cabinet Mode (`0x0052`). Adds \
     the RapidCool and RapidFreeze mode tags."
);

derived_mode_cluster!(
    rvc_run_mode,
    "RVC Run Mode (`0x0054`). Adds the Idle, Cleaning and Mapping mode tags, \
     the Stuck / DustBinFull / WaterTankEmpty / BatteryLow family of status \
     codes, and the `DIRECT_MODE_CHANGE` feature."
);

derived_mode_cluster!(
    rvc_clean_mode,
    "RVC Clean Mode (`0x0055`). Adds the DeepClean, Vacuum, Mop and \
     VacuumThenMop mode tags, the CleaningInProgress status code, and the \
     `DIRECT_MODE_CHANGE` feature."
);

derived_mode_cluster!(
    dishwasher_mode,
    "Dishwasher Mode (`0x0059`). Adds the Normal, Heavy and Light mode tags; \
     at least one mode must carry Normal."
);

derived_mode_cluster!(
    microwave_oven_mode,
    "Microwave Oven Mode (`0x005E`). Adds the Normal and Defrost mode tags.\n\n\
     The one derived cluster with **no `ChangeToMode` command**: its \
     `CurrentMode` is driven by the Microwave Oven Control cluster on the \
     same endpoint, so this handler serves the two attributes read-only and \
     [`ModeHooks::change_to_mode`] is never called.",
    read_only
);

derived_mode_cluster!(
    energy_evse_mode,
    "Energy EVSE Mode (`0x009D`). Adds the Manual, TimeOfUse and \
     SolarCharging mode tags."
);

derived_mode_cluster!(
    water_heater_mode,
    "Water Heater Mode (`0x009E`). Adds the Off, Manual and Timed mode tags."
);

derived_mode_cluster!(
    device_energy_management_mode,
    "Device Energy Management Mode (`0x009F`). Adds the NoOptimization, \
     DeviceOptimization, LocalOptimization and GridOptimization mode tags."
);

#[cfg(test)]
mod tests {
    //! Unit tests for the parts of [`ModeHandler`] that need no `Matter` /
    //! `InvokeContext` setup: mode-table lookup, the startup validation
    //! rules, and the tag-range classification the validation leans on.

    use core::cell::Cell;

    use crate::dm::clusters::decl::rvc_run_mode;
    use crate::dm::Dataver;
    use crate::utils::sync::blocking::Mutex;
    use crate::with;

    use super::*;

    type RunTag = rvc_run_mode::ModeTag;

    struct TestHooks<'a> {
        modes: &'a [Mode<'a, RunTag>],
        current: Mutex<Cell<ModeId>>,
    }

    impl<'a> TestHooks<'a> {
        fn new(modes: &'a [Mode<'a, RunTag>], current: ModeId) -> Self {
            Self {
                modes,
                current: Mutex::new(Cell::new(current)),
            }
        }
    }

    impl ModeHooks for TestHooks<'_> {
        const CLUSTER: Cluster<'static> = rvc_run_mode::FULL_CLUSTER.with_attrs(with!(required));

        type ModeTag = RunTag;

        fn supported_modes(&self) -> &[Mode<'_, RunTag>] {
            self.modes
        }

        fn current_mode(&self) -> ModeId {
            self.current.lock(|c| c.get())
        }

        fn change_to_mode(&self, mode: ModeId) -> Result<(), ModeChangeError> {
            self.current.lock(|c| c.set(mode));

            Ok(())
        }
    }

    fn handler<'a>(modes: &'a [Mode<'a, RunTag>], current: ModeId) -> ModeHandler<TestHooks<'a>> {
        ModeHandler::new(Dataver::new(0), TestHooks::new(modes, current))
    }

    const IDLE: ModeTag<RunTag> = ModeTag::Standard(RunTag::Idle);
    const CLEANING: ModeTag<RunTag> = ModeTag::Standard(RunTag::Cleaning);
    const AUTO: ModeTag<RunTag> = ModeTag::Standard(RunTag::Auto);

    const GOOD: &[Mode<RunTag>] = &[
        Mode::new(0, "Idle", &[IDLE]),
        Mode::new(1, "Cleaning", &[CLEANING, AUTO]),
    ];

    #[test]
    fn tag_ranges_classify_standard_versus_manufacturer() {
        assert!(ModeTag::<RunTag>::Standard(RunTag::LowEnergy).is_standard());
        assert!(IDLE.is_standard());
        assert!(!ModeTag::<RunTag>::manufacturer(0xFFF1, 0x8000).is_standard());
    }

    #[test]
    #[should_panic(expected = "0x8000..=0xBFFF")]
    fn manufacturer_tag_rejects_a_standard_range_value() {
        // Would collide with the cluster's own namespace.
        let _ = ModeTag::<RunTag>::manufacturer(0xFFF1, 0x4000);
    }

    #[test]
    #[should_panic(expected = "0x40..=0x7F")]
    fn derived_status_rejects_a_common_range_code() {
        let _ = ModeChangeError::derived(CommonStatusCode::InvalidInMode as u8, "nope");
    }

    #[test]
    fn tag_sets_compare_without_regard_to_order() {
        type H<'a> = ModeHandler<TestHooks<'a>>;

        assert!(H::same_tag_set(&[IDLE, AUTO], &[AUTO, IDLE]));
        // A subset is distinct from its superset - which the spec allows.
        assert!(!H::same_tag_set(&[IDLE], &[IDLE, AUTO]));
    }

    #[test]
    fn lookup_by_mode_and_by_tag() {
        let handler = handler(GOOD, 0);

        assert!(handler.is_supported_mode(1));
        assert!(!handler.is_supported_mode(2));

        assert_eq!(handler.mode_by_tag(CLEANING), Some(1));
        assert_eq!(handler.mode_by_tag(ModeTag::Standard(RunTag::Night)), None);
    }

    #[test]
    fn a_spec_compliant_table_validates() {
        handler(GOOD, 0).validate();
    }

    #[test]
    #[should_panic(expected = "at least 2 entries")]
    fn a_single_mode_is_rejected() {
        const MODES: &[Mode<RunTag>] = &[Mode::new(0, "Idle", &[IDLE])];

        handler(MODES, 0).validate();
    }

    #[test]
    #[should_panic(expected = "share the Mode value")]
    fn duplicate_mode_values_are_rejected() {
        const MODES: &[Mode<RunTag>] = &[
            Mode::new(0, "Idle", &[IDLE]),
            Mode::new(0, "Cleaning", &[CLEANING]),
        ];

        handler(MODES, 0).validate();
    }

    #[test]
    #[should_panic(expected = "share the Label")]
    fn duplicate_labels_are_rejected() {
        const MODES: &[Mode<RunTag>] = &[
            Mode::new(0, "Idle", &[IDLE]),
            Mode::new(1, "Idle", &[CLEANING]),
        ];

        handler(MODES, 0).validate();
    }

    #[test]
    #[should_panic(expected = "identical mode tag sets")]
    fn duplicate_tag_sets_are_rejected() {
        const MODES: &[Mode<RunTag>] = &[
            Mode::new(0, "One", &[IDLE, AUTO]),
            Mode::new(1, "Two", &[AUTO, IDLE]),
        ];

        handler(MODES, 0).validate();
    }

    #[test]
    #[should_panic(expected = "repeats a mode tag")]
    fn a_mode_repeating_a_tag_is_rejected() {
        // Spec: the tags within one mode must be distinct - `[Auto, Auto]` is
        // not allowed. CHIP's `ModeBaseClusterChecks` enforces this too.
        const MODES: &[Mode<RunTag>] = &[
            Mode::new(0, "Idle", &[IDLE]),
            Mode::new(1, "Cleaning", &[AUTO, AUTO]),
        ];

        handler(MODES, 0).validate();
    }

    #[test]
    #[should_panic(expected = "no standard mode tag")]
    fn a_mode_without_a_standard_tag_is_rejected() {
        const MODES: &[Mode<RunTag>] = &[
            Mode::new(0, "Idle", &[IDLE]),
            Mode::new(1, "Custom", &[ModeTag::manufacturer(0xFFF1, 0x8000)]),
        ];

        handler(MODES, 0).validate();
    }

    #[test]
    #[should_panic(expected = "no mode tags")]
    fn an_untagged_mode_is_rejected() {
        const MODES: &[Mode<RunTag>] = &[
            Mode::new(0, "Idle", &[IDLE]),
            Mode::new(1, "Anonymous", &[]),
        ];

        handler(MODES, 0).validate();
    }

    #[test]
    fn a_dropped_current_mode_falls_back_to_the_first_entry() {
        // What a firmware update that removes a mode leaves behind: a
        // persisted CurrentMode with nothing to point at. Not a bug, so it is
        // repaired rather than fatal.
        let handler = handler(GOOD, 7);

        handler.repair_current_mode();

        assert_eq!(handler.current_mode(), 0);
    }

    #[test]
    fn a_valid_current_mode_is_left_alone() {
        let handler = handler(GOOD, 1);

        handler.repair_current_mode();

        assert_eq!(handler.current_mode(), 1);
    }
}
