// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Error messages that the server sends for LDK Node errors that a client can act on.
//!
//! The server sends the LDK Node error text as the gRPC message. A test of the server compares
//! these constants with LDK Node, so an LDK Node update that changes a text fails that test.

/// The message of `NodeError::NotRunning`, with code `InternalServerError`. LDK Node checks
/// this before it runs a call, so the call did nothing.
pub const NOT_RUNNING: &str = "Node is not running.";

/// The message of `NodeError::DuplicatePayment`, with code `LightningError`. LDK Node already
/// tracks a payment with the same payment ID.
pub const DUPLICATE_PAYMENT: &str = "A payment with the given hash has already been initiated.";
