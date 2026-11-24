// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! RPC permission requirements.

pub(crate) use ldk_server_grpc::permissions::{method_authorization, MethodAuthorization};

#[cfg(test)]
mod tests {
	use std::collections::BTreeSet;

	use ldk_server_grpc::endpoints::GET_PERMISSIONS_PATH;
	use ldk_server_grpc::permissions::ALL_PERMISSIONS;

	use super::*;
	use crate::macaroons::MacaroonInfo;

	/// The permissions of the macaroon of a CDK payment processor, the credential that a mint
	/// uses. The README of the processor names the same five.
	const PROCESSOR_PERMISSIONS: [&str; 5] =
		["node:read", "invoices:create", "payments:read", "payments:send", "events:read"];

	fn declared_methods() -> BTreeSet<&'static str> {
		include_str!("../../../ldk-server-grpc/src/proto/api.proto")
			.lines()
			.filter_map(|line| {
				let mut words = line.split_whitespace();
				if words.next() != Some("rpc") {
					return None;
				}
				Some(words.next().expect("RPC name").split('(').next().unwrap())
			})
			.collect()
	}

	#[test]
	fn every_rpc_has_the_expected_authorization() {
		// Keep this contract independent of the production mapping. The schema comparison
		// requires each new RPC to have an explicit authorization expectation here.
		let expected = [
			("GetNodeInfo", Some("node:read")),
			("GetBalances", Some("node:read")),
			("OnchainReceive", Some("onchain:receive")),
			("OnchainSend", Some("onchain:send")),
			("OnchainBumpFee", Some("onchain:send")),
			("Bolt11Receive", Some("invoices:create")),
			("Bolt11ReceiveForHash", Some("invoices:create")),
			("Bolt11ClaimForId", Some("payments:claim")),
			("Bolt11FailForId", Some("payments:claim")),
			("Bolt11ReceiveViaJitChannel", Some("invoices:create")),
			("Bolt11ReceiveVariableAmountViaJitChannel", Some("invoices:create")),
			("Bolt11ReceiveViaJitChannelForHash", Some("invoices:create")),
			("Bolt11ReceiveVariableAmountViaJitChannelForHash", Some("invoices:create")),
			("Bolt11Send", Some("payments:send")),
			("Bolt11SendProbes", Some("payments:send_advanced")),
			("Bolt11SendUnderpaying", Some("payments:send_advanced")),
			("Bolt12Receive", Some("invoices:create")),
			("Bolt12Send", Some("payments:send")),
			("Bolt12SendRefund", Some("payments:send_advanced")),
			("Bolt12ReceiveRefund", Some("invoices:create")),
			("Bolt12CreatePayerProof", Some("messages:sign")),
			("SpontaneousSend", Some("payments:send_advanced")),
			("SpontaneousSendProbes", Some("payments:send_advanced")),
			("OpenChannel", Some("channels:manage")),
			("SpliceIn", Some("channels:manage")),
			("SpliceOut", Some("channels:manage")),
			("BumpChannelFundingFee", Some("channels:manage")),
			("UpdateChannelConfig", Some("channels:manage")),
			("CloseChannel", Some("channels:manage")),
			("ForceCloseChannel", Some("channels:force_close")),
			("ListChannels", Some("channels:read")),
			("GetPaymentDetails", Some("payments:read")),
			("ListPayments", Some("payments:read")),
			("ListForwardedPayments", Some("payments:read")),
			("GetForwardedPaymentDetails", Some("payments:read")),
			("GetForwardedPaymentTrackingMode", Some("payments:read")),
			("GetChannelForwardingStats", Some("payments:read")),
			("ListChannelForwardingStats", Some("payments:read")),
			("ListChannelPairForwardingStats", Some("payments:read")),
			("ConnectPeer", Some("peers:manage")),
			("DisconnectPeer", Some("peers:manage")),
			("ListPeers", Some("peers:read")),
			("SignMessage", Some("messages:sign")),
			("VerifySignature", Some("messages:verify")),
			("ExportPathfindingScores", Some("node:read")),
			("UnifiedSend", Some("onchain:send")),
			("DecodeInvoice", Some("utilities:read")),
			("DecodeOffer", Some("utilities:read")),
			("GraphListChannels", Some("graph:read")),
			("GraphGetChannel", Some("graph:read")),
			("GraphListNodes", Some("graph:read")),
			("GraphGetNode", Some("graph:read")),
			("SubscribeEvents", Some("events:read")),
			("CreateMacaroon", Some("macaroons:manage")),
			("ListMacaroons", Some("macaroons:manage")),
			("RevokeMacaroon", Some("macaroons:manage")),
			("GetPermissions", None),
		];
		let declared_methods = declared_methods();
		let tested_methods: BTreeSet<_> = expected.iter().map(|(method, _)| *method).collect();
		assert_eq!(tested_methods.len(), expected.len(), "Duplicate RPC in permission table");
		assert_eq!(declared_methods, tested_methods, "Update the RPC permission test table");

		for (method, expected_permission) in expected {
			let required = match (method_authorization(method), expected_permission) {
				(MethodAuthorization::Permission(actual), Some(expected)) => {
					assert_eq!(actual, expected, "Incorrect permission for {method}");
					actual
				},
				(MethodAuthorization::AuthenticatedOnly, None) => continue,
				_ => panic!("Incorrect authorization classification for {method}"),
			};
			assert!(ALL_PERMISSIONS.contains(&required), "Unknown permission for {method}");
			let mut info = MacaroonInfo {
				id: "test".to_string(),
				name: "test".to_string(),
				permissions: BTreeSet::new(),
				caveats: Vec::new(),
			};
			assert!(
				!info.allows(required),
				"Identity without permissions must not access {method}"
			);
			for permission in ALL_PERMISSIONS {
				info.permissions = BTreeSet::from([permission.to_string()]);
				assert_eq!(
					info.allows(required),
					permission == "admin" || permission == required,
					"Unexpected access to {method} with {permission}"
				);
			}
		}
	}

	#[test]
	fn processor_macaroon_permits_only_decided_methods() {
		// A processor credential must not send on-chain funds or channel funds to an address, and
		// must pay only BOLT11 invoices and BOLT12 offers. A method that gets one of these
		// permissions fails this test until someone decides that a processor may call it.
		let decided = BTreeSet::from([
			// The processor calls these methods.
			"GetNodeInfo",
			"Bolt11Receive",
			"Bolt12Receive",
			"Bolt11Send",
			"Bolt12Send",
			"GetPaymentDetails",
			"ListPayments",
			"SubscribeEvents",
			// The processor does not call these methods. They share a permission with a method
			// above, and they send no funds.
			"GetBalances",
			"ExportPathfindingScores",
			"Bolt11ReceiveForHash",
			"Bolt11ReceiveViaJitChannel",
			"Bolt11ReceiveVariableAmountViaJitChannel",
			"Bolt11ReceiveViaJitChannelForHash",
			"Bolt11ReceiveVariableAmountViaJitChannelForHash",
			"Bolt12ReceiveRefund",
			"ListForwardedPayments",
			"GetForwardedPaymentDetails",
			"GetForwardedPaymentTrackingMode",
			"GetChannelForwardingStats",
			"ListChannelForwardingStats",
			"ListChannelPairForwardingStats",
			// Every authenticated caller may use this method.
			"GetPermissions",
		]);
		let permitted: BTreeSet<_> = declared_methods()
			.into_iter()
			.filter(|method| match method_authorization(method) {
				MethodAuthorization::Permission(required) => {
					PROCESSOR_PERMISSIONS.contains(&required)
				},
				MethodAuthorization::AuthenticatedOnly => true,
				MethodAuthorization::Unknown => false,
			})
			.collect();
		assert_eq!(permitted, decided);
	}

	#[test]
	fn permissionless_and_unknown_methods_have_explicit_classification() {
		assert!(matches!(
			method_authorization(GET_PERMISSIONS_PATH),
			MethodAuthorization::AuthenticatedOnly
		));
		assert!(matches!(
			method_authorization("FutureUnclassifiedRpc"),
			MethodAuthorization::Unknown
		));
	}
}
