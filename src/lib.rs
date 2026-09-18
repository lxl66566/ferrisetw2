//! # Event Windows Tracing FTW!
//! This crate provides safe Rust abstractions over the ETW consumer APIs.
//!
//! It started as a [KrabsETW](https://github.com/microsoft/krabsetw/) rip-off written in Rust (hence the name [`Ferris`](https://rustacean.net/) 🦀).
//! All credits go to the team at Microsoft who develop KrabsEtw, without it, this project probably
//! wouldn't be a thing.<br/> Since version 1.0, the API and internal architecture of this crate is
//! slightly diverging from `krabsetw`, so that it is more Rust-idiomatic.
//!
//! # What's ETW
//! Event Tracing for Windows (ETW) is an efficient kernel-level tracing facility that lets you log
//! kernel or application-defined events to a log file. You can consume the events in real time or
//! from a log file and use them to debug an application or to determine where performance issues
//! are occurring in the application. [Source]
//!
//! ETW is made out of three components:
//! * Controllers
//! * Providers
//! * Consumers
//!
//! This crate provides the means to start and stop a controller, enable/disable providers and
//! finally to consume the events within our own defined callback.<br/>
//! It is also able to process events from a file instead of a real-time trace session.
//!
//! # Motivation
//! Even though ETW is a extremely powerful tracing mechanism, interacting with it is not easy by
//! any means. There's a lot of details and caveats that have to be taken into consideration in
//! order to make it work. On the other hand, once we manage to start consuming a trace session in
//! real-time we have to deal with the process of finding the Schema and parsing the properties. All
//! this process can be tedious and cumbersome, therefore tools like KrabsETW come in very handy to
//! simplify the interaction with ETW.
//!
//! Since lately I've been working very closely with ETW and Rust, I thought that having a tool that
//! would simplify ETW management written in Rust and available as a crate for other to consume
//! would be pretty neat and that's where this crate comes into play 🔥
//!
//! # Getting started
//! If you are familiar with KrabsEtw you'll see using the crate is very similar, in case you are
//! not familiar with it the following example shows the basics on how to build a provider, start a
//! trace and handle the Event in the callback
// The example body lives in `getting_started.md`, out of rustfmt's sight: rustfmt cannot see
// the cfg_attr-hidden doctest fence and would rewrap the whole example as prose.
// The example starts a real ETW trace session (admin-only): run it with the `admin_tests`
// feature, otherwise it is only type-checked (`no_run`).
#![cfg_attr(feature = "admin_tests", doc = "```")]
#![cfg_attr(not(feature = "admin_tests"), doc = "```no_run")]
#![doc = include_str!("getting_started.md")]
// Both fence variants must exist for opening AND closing, otherwise the attribute
// expands to nothing under one of the feature states and the block is left unclosed.
#![cfg_attr(feature = "admin_tests", doc = "```")]
#![cfg_attr(not(feature = "admin_tests"), doc = "```")]
//! [KrabsETW]: https://github.com/microsoft/krabsetw/
//! [Source]: https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing
//!
//! # Log messages
//! ferrisetw may (very) occasionally write error log messages using the [`log`](https://docs.rs/log/latest/log/) crate.<br/>
//! In case you want them to be printed to the console, your binary should use one of the various logger implementations. [`env_logger`](https://docs.rs/env_logger/latest/env_logger/) is one of them.<br/>
//! You can have a look at how to use it in the `examples/` folder in the GitHub repository.
//!
//! # Callback panics
//! The callbacks you register on a provider (see
//! [`crate::provider::ProviderBuilder::add_callback`]) are invoked by Windows itself, on ETW
//! delivery threads: a panic must not unwind across that FFI boundary, as unwinding into
//! `extern "system"` native code is undefined behavior. ferrisetw therefore catches panics at
//! that boundary, logs them through the [`log`](https://docs.rs/log/latest/log/) crate, and
//! **terminates the process with exit code 1**: a callback that panicked midway may have left
//! your own state (counters, aggregators, ...) inconsistent, so silently dropping the
//! following events is not a safer outcome.
//!
//! In short, a panicking callback brings the whole process down by design. If your callbacks
//! process untrusted or unexpected events, catch (and handle) the panics within the callback
//! itself.
//!
//! # Migrating from 1.x
//! Version 2.0 removes two public API surfaces:
//! * `UserTrace::stop` and `KernelTrace::stop` lost their inherent methods: bring the
//!   [`crate::trace::TraceTrait`] trait into scope to call `stop` on any trace.
//! * The `ferrisetw::traits` module (the `EncodeUtf16` helper) was folded into the parser and
//!   removed.

#[macro_use]
extern crate memoffset;

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate num_derive;
extern crate num_traits;

pub mod native;
pub mod parser;
mod property;
pub mod provider;
pub mod query;
pub mod schema;
pub mod schema_locator;
pub mod ser;
pub mod trace;
mod utils;

pub(crate) type EtwCallback = Box<dyn FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static>;

// Convenience re-exports.
/// Re-exported `GUID` from `windows-rs`, which is used in return values for some functions of
/// this crate
pub use windows::core::GUID;

// These types are returned by some public APIs of this crate.
// They must be re-exported, so that users of the crate have a way to avoid version conflicts
// (see https://github.com/n4r1b/ferrisetw/issues/46)
/// Owned security identifier returned in extended data of some events
/// (see [`ExtendedDataItem::Sid`](crate::native::ExtendedDataItem::Sid))
pub use crate::native::Sid;
#[cfg(feature = "serde")]
pub use crate::ser::{EventSerializer, EventSerializerOptions};
pub use crate::{
    native::etw_types::event_record::EventRecord,
    schema_locator::SchemaLocator,
    trace::{FileTrace, KernelTrace, UserTrace},
};
