// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use e2e_tests::{
	assert_recovered_balance, close_channel, expected_onchain_balance, list_payments,
	mine_and_sync, send_bolt11_payment, setup_funded_channel, start_expect_failure,
	start_expect_failure_within, wait_for_channels, wait_for_force_close_claims,
	wait_for_forwarded_payments, wait_for_gossip, wait_for_settled_balance,
	wait_for_usable_channel, LdkServerHandle, TestBitcoind, TestConfigBuilder, TestServerParams,
};
use ldk_server_grpc::api::{
	open_channel_request, ConnectPeerRequest, DisconnectPeerRequest, ForceCloseChannelRequest,
	GetBalancesRequest, GetBalancesResponse, GetNodeInfoRequest, ListChannelForwardingStatsRequest,
	OnchainReceiveRequest, OpenChannelRequest,
};
use ldk_server_grpc::types::{lightning_balance, payment_kind, BalanceSource, PaymentStatus};

const TIMEOUT: Duration = Duration::from_secs(60);

/// Wait until all funds are claimable on the expected open channels, without outstanding
/// outgoing HTLC claims or dust rounding. An inbound HTLC with a known preimage can still
/// be in the commitment at this point; its value is already included in the claimable amount.
async fn open_channel_balances(server: &LdkServerHandle, count: usize) -> GetBalancesResponse {
	let start = Instant::now();
	loop {
		let balances = server.client().get_balances(GetBalancesRequest {}).await.unwrap();
		if balances.lightning_balances.len() == count
			&& balances.pending_balances_from_channel_closures.is_empty()
			&& balances.lightning_balances.iter().all(|balance| {
				matches!(
					balance.balance_type.as_ref(),
					Some(lightning_balance::BalanceType::ClaimableOnChannelClose(claim))
						if claim.outbound_payment_htlc_rounded_msat == 0
							&& claim.outbound_forwarded_htlc_rounded_msat == 0
							&& claim.inbound_claiming_htlc_rounded_msat == 0
							&& claim.inbound_htlc_rounded_msat == 0
				)
			}) {
			return balances;
		}
		assert!(
			start.elapsed() < TIMEOUT,
			"Waiting for {count} open channel balances: {balances:?}"
		);
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

/// Compare funds, including commitment fees, independently for each channel. Removing an
/// already-claimed inbound HTLC reduces the commitment fee and increases the claimable
/// amount by the same value. That may finish during restart without changing our funds.
fn channel_funds(balances: &GetBalancesResponse) -> BTreeMap<String, u64> {
	let mut total_claimable = 0;
	let mut funds = BTreeMap::new();
	for balance in &balances.lightning_balances {
		let Some(lightning_balance::BalanceType::ClaimableOnChannelClose(claim)) =
			&balance.balance_type
		else {
			panic!("Expected open channel balance: {balance:?}");
		};
		total_claimable += claim.amount_satoshis;
		assert!(funds
			.insert(
				claim.channel_id.clone(),
				claim.amount_satoshis + claim.transaction_fee_satoshis
			)
			.is_none());
	}
	assert_eq!(balances.total_lightning_balance_sats, total_claimable);
	funds
}

#[test]
fn test_channel_funds_preserve_exact_value_across_fee_changes() {
	let balances = |amount_satoshis, transaction_fee_satoshis| GetBalancesResponse {
		total_lightning_balance_sats: amount_satoshis,
		lightning_balances: vec![ldk_server_grpc::types::LightningBalance {
			balance_type: Some(lightning_balance::BalanceType::ClaimableOnChannelClose(
				ldk_server_grpc::types::ClaimableOnChannelClose {
					channel_id: "channel".to_string(),
					amount_satoshis,
					transaction_fee_satoshis,
					..Default::default()
				},
			)),
		}],
		..Default::default()
	};
	// Reproduce the observed 43-sat change when the final HTLC leaves the commitment.
	let before = channel_funds(&balances(919_014, 327));
	assert_eq!(before, BTreeMap::from([("channel".to_string(), 919_341)]));
	assert_eq!(before, channel_funds(&balances(919_057, 284)));
	// A real one-satoshi loss must still fail the persistence comparison.
	assert_ne!(before, channel_funds(&balances(919_056, 284)));
}

async fn start_postgres(bitcoind: &TestBitcoind, connection_string: &str) -> LdkServerHandle {
	let server = LdkServerHandle::start_with_config(bitcoind, |params| {
		// Each server gets its own table, even when sharing the same test database.
		// Ports may be reused by a later test process against the same database.
		let directory = params.storage_dir.file_name().unwrap().to_str().unwrap();
		let table_name = format!("node_{}", directory.replace('.', "_"));
		TestConfigBuilder::new(params)
			.postgres(connection_string, &table_name)
			.allow_new_postgres_node()
			.forwarded_payment_tracking_mode("detailed")
			.log(Some("Info"), params.storage_dir.join("ldk-server.log").to_str().unwrap())
			.build()
	})
	.await;
	assert!(server.storage_dir.join("regtest/ldk_node_postgres.lock").exists());
	assert!(!server.storage_dir.join("regtest/ldk_node_data.sqlite").exists());
	// A restart with the flag refuses, so remove it after the first start, as an operator does.
	let config = std::fs::read_to_string(&server.config_path).unwrap();
	assert!(config.contains("allow_new_node = true\n"));
	std::fs::write(&server.config_path, config.replace("allow_new_node = true\n", "")).unwrap();
	server
}

/// A start on a PostgreSQL table without node data refuses unless `allow_new_node` is set: the
/// table can be an empty or wrong database for an existing node identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore = "requires PostgreSQL; set POSTGRES_CONNECTION_STRING"]
async fn test_postgres_refuses_a_table_without_node_data() {
	let connection_string = std::env::var("POSTGRES_CONNECTION_STRING")
		.expect("Set POSTGRES_CONNECTION_STRING to a disposable PostgreSQL database");
	let bitcoind = TestBitcoind::new();
	let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
	let table_name = format!("new_node_{}_{nanos}", std::process::id());

	// The second refusal shows that the first one stored no ChannelManager.
	for _ in 0..2 {
		let stderr = start_expect_failure(&bitcoind, |params| {
			TestConfigBuilder::new(params).postgres(&connection_string, &table_name).build()
		});
		assert!(stderr.contains("holds no LDK Node data"), "{stderr}");
	}

	let mut server = LdkServerHandle::start_with_config(&bitcoind, |params| {
		TestConfigBuilder::new(params)
			.postgres(&connection_string, &table_name)
			.allow_new_postgres_node()
			.build()
	})
	.await;
	let with_flag = std::fs::read_to_string(&server.config_path).unwrap();
	let without_flag = with_flag.replace("allow_new_node = true\n", "");

	// A started new node has its ChannelManager stored, before a block or a channel and without
	// a graceful stop. Thus the next start needs no flag.
	server.kill();
	std::fs::write(&server.config_path, &without_flag).unwrap();
	server.start_again().await;

	// With node data, the flag is stale. A start with it refuses, so that a flag that stays in
	// the configuration cannot create a node after the database changed.
	server.stop().await;
	std::fs::write(&server.config_path, with_flag).unwrap();
	let stderr = server.start_again_expect_failure();
	assert!(stderr.contains("allow_new_node is set, but"), "{stderr}");
	std::fs::write(&server.config_path, &without_flag).unwrap();
	server.start_again().await;
}

fn psql(connection_string: &str, sql: &str) {
	let output = std::process::Command::new("psql")
		.args([connection_string, "-v", "ON_ERROR_STOP=1", "-qc", sql])
		.output()
		.expect("Failed to run psql");
	assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

/// A stop of LDK Node returns success also when its last ChannelManager write did not complete. A
/// first start must not serve without a stored ChannelManager.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore = "requires PostgreSQL and psql; set POSTGRES_CONNECTION_STRING with a database name"]
async fn test_postgres_first_start_refuses_without_a_stored_channel_manager() {
	let connection_string = std::env::var("POSTGRES_CONNECTION_STRING")
		.expect("Set POSTGRES_CONNECTION_STRING to a disposable PostgreSQL database");
	let bitcoind = TestBitcoind::new();
	let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
	let table_name = format!("lost_write_{}_{nanos}", std::process::id());
	let config = |params: &TestServerParams, allow_new_node: bool| {
		// Each start has its own storage directory, but the node of the table has one identity.
		std::fs::write(
			params.storage_dir.join("keys_mnemonic"),
			"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong\n",
		)
		.unwrap();
		let builder = TestConfigBuilder::new(params).postgres(&connection_string, &table_name);
		if allow_new_node { builder.allow_new_postgres_node() } else { builder }.build()
	};

	// A refused start creates the table. Then the database drops each ChannelManager write, and
	// reports success for it.
	let stderr = start_expect_failure(&bitcoind, |params| config(params, false));
	assert!(stderr.contains("holds no LDK Node data"), "{stderr}");
	psql(
		&connection_string,
		&format!(
			"CREATE FUNCTION {table_name}_drop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
			 IF NEW.key = 'manager' THEN RETURN NULL; END IF; RETURN NEW; END $$; \
			 CREATE TRIGGER lost_write BEFORE INSERT ON {table_name} \
			 FOR EACH ROW EXECUTE FUNCTION {table_name}_drop()"
		),
	);
	let stderr = start_expect_failure(&bitcoind, |params| config(params, true));
	assert!(stderr.contains("has no ChannelManager in PostgreSQL"), "{stderr}");
	assert!(stderr.contains("start again with allow_new_node = true"), "{stderr}");

	// The next step that the error names works.
	psql(&connection_string, &format!("DROP TRIGGER lost_write ON {table_name}"));
	LdkServerHandle::start_with_config(&bitcoind, |params| config(params, true)).await;
}

/// The store lease: a second node on the store of a running node refuses to start, and the running
/// node keeps its lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL; set POSTGRES_CONNECTION_STRING"]
async fn test_postgres_second_start_refuses_while_the_lease_is_live() {
	let connection_string = std::env::var("POSTGRES_CONNECTION_STRING")
		.expect("Set POSTGRES_CONNECTION_STRING to a disposable PostgreSQL database");
	let bitcoind = TestBitcoind::new();
	let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
	let table_name = format!("lease_{}_{nanos}", std::process::id());
	let server = LdkServerHandle::start_with_config(&bitcoind, |params| {
		TestConfigBuilder::new(params)
			.postgres(&connection_string, &table_name)
			.allow_new_postgres_node()
			.build()
	})
	.await;

	// A start waits up to 60 s for a stale lease, which is longer than two lease periods. The
	// running node renews its lease, so the wait ends with a refusal.
	let stderr = start_expect_failure_within(&bitcoind, Duration::from_secs(120), |params| {
		TestConfigBuilder::new(params).postgres(&connection_string, &table_name).build()
	});
	assert!(stderr.contains("PostgreSQL node lease is unavailable"), "{stderr}");

	// A node that lost its lease aborts at its next write. This call writes wallet data.
	server.client().onchain_receive(OnchainReceiveRequest {}).await.unwrap();
	server.client().get_node_info(GetNodeInfoRequest {}).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore = "requires PostgreSQL; set POSTGRES_CONNECTION_STRING"]
async fn test_postgres_table_isolation() {
	let connection_string = std::env::var("POSTGRES_CONNECTION_STRING")
		.expect("Set POSTGRES_CONNECTION_STRING to a disposable PostgreSQL database");
	let bitcoind = TestBitcoind::new();
	// Both processes must run concurrently. Ignoring kv_table_name would make the second
	// process contend for the first process's PostgreSQL store lock.
	let mut servers = [
		start_postgres(&bitcoind, &connection_string).await,
		start_postgres(&bitcoind, &connection_string).await,
	];
	assert_ne!(servers[0].node_id(), servers[1].node_id());

	let address_a = servers[0].client().onchain_receive(OnchainReceiveRequest {}).await.unwrap();
	bitcoind.fund_address(&address_a.address, 0.01);
	mine_and_sync(&bitcoind, &[&servers[0], &servers[1]], 6).await;
	wait_for_settled_balance(&servers[0], 1_000_000, TIMEOUT).await;
	wait_for_settled_balance(&servers[1], 0, TIMEOUT).await;
	assert!(list_payments(&servers[1]).await.is_empty());

	let address_b = servers[1].client().onchain_receive(OnchainReceiveRequest {}).await.unwrap();
	assert_ne!(address_a.address, address_b.address);
	bitcoind.fund_address(&address_b.address, 0.02);
	mine_and_sync(&bitcoind, &[&servers[0], &servers[1]], 6).await;
	for (server, expected_sats) in servers.iter_mut().zip([1_000_000, 2_000_000]) {
		// Wait for the funding payment to be confirmed before comparing persisted records.
		assert_eq!(
			expected_onchain_balance(&bitcoind, server, 0, &[], 1, TIMEOUT).await,
			expected_sats
		);
		wait_for_settled_balance(server, expected_sats, TIMEOUT).await;
		let saved_payments = list_payments(server).await;
		server.restart().await;
		wait_for_settled_balance(server, expected_sats, TIMEOUT).await;
		assert_eq!(list_payments(server).await, saved_payments);
	}
	wait_for_settled_balance(&servers[0], 1_000_000, TIMEOUT).await;
	wait_for_settled_balance(&servers[1], 2_000_000, TIMEOUT).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore = "requires PostgreSQL; set POSTGRES_CONNECTION_STRING"]
async fn test_postgres_persistence_and_sqlite_interoperability() {
	let connection_string = std::env::var("POSTGRES_CONNECTION_STRING")
		.expect("Set POSTGRES_CONNECTION_STRING to a disposable PostgreSQL database");
	let bitcoind = TestBitcoind::new();
	let sqlite_a = LdkServerHandle::start(&bitcoind).await;
	let mut postgres = start_postgres(&bitcoind, &connection_string).await;
	let sqlite_c = LdkServerHandle::start(&bitcoind).await;
	let first_address = postgres.client().onchain_receive(OnchainReceiveRequest {}).await.unwrap();

	// SQLite A -> PostgreSQL B -> SQLite C. B both accepts and initiates a channel.
	let channel_ab = setup_funded_channel(&bitcoind, &sqlite_a, &postgres, 1_000_000).await;
	let channel_bc = setup_funded_channel(&bitcoind, &postgres, &sqlite_c, 1_000_000).await;
	wait_for_channels(&sqlite_a, 1, TIMEOUT).await;
	wait_for_channels(&postgres, 2, TIMEOUT).await;
	wait_for_channels(&sqlite_c, 1, TIMEOUT).await;
	wait_for_gossip(&sqlite_a, 2, TIMEOUT).await;
	wait_for_gossip(&sqlite_c, 2, TIMEOUT).await;

	// Check that the test really selected different backends.
	for sqlite in [&sqlite_a, &sqlite_c] {
		assert!(sqlite.storage_dir.join("regtest/ldk_node_data.sqlite").exists());
		assert!(!sqlite.storage_dir.join("regtest/ldk_node_postgres.lock").exists());
	}

	send_bolt11_payment(&sqlite_a, &postgres, 50_000_000).await;
	send_bolt11_payment(&postgres, &sqlite_a, 10_000_000).await;
	send_bolt11_payment(&postgres, &sqlite_c, 50_000_000).await;
	send_bolt11_payment(&sqlite_c, &postgres, 10_000_000).await;
	send_bolt11_payment(&sqlite_a, &sqlite_c, 50_000_000).await;
	send_bolt11_payment(&sqlite_c, &sqlite_a, 10_000_000).await;
	let saved_forwards = wait_for_forwarded_payments(&postgres, 2, TIMEOUT).await;
	for (from, to) in [(&sqlite_a, &sqlite_c), (&sqlite_c, &sqlite_a)] {
		assert!(saved_forwards.iter().any(|p| {
			p.prev_node_id.as_deref() == Some(from.node_id())
				&& p.next_node_id.as_deref() == Some(to.node_id())
		}));
	}
	let saved_payments = list_payments(&postgres).await;
	assert_eq!(
		saved_payments
			.iter()
			.filter(|p| {
				p.status == PaymentStatus::Succeeded as i32
					&& matches!(
						p.kind.as_ref().and_then(|kind| kind.kind.as_ref()),
						Some(payment_kind::Kind::Bolt11(_))
					)
			})
			.count(),
		4
	);
	let saved_channels = wait_for_channels(&postgres, 2, TIMEOUT).await;
	let saved_balances = open_channel_balances(&postgres, 2).await;
	let saved_channel_funds = channel_funds(&saved_balances);
	assert!(saved_balances.total_onchain_balance_sats > 0);
	assert!(saved_balances.total_lightning_balance_sats > 0);
	let saved_stats = postgres
		.client()
		.list_channel_forwarding_stats(ListChannelForwardingStatsRequest { page_token: None })
		.await
		.unwrap();
	assert_eq!(saved_stats.stats.len(), 2);
	let address_before = postgres.client().onchain_receive(OnchainReceiveRequest {}).await.unwrap();

	// A process kill tests committed state without relying on a graceful shutdown flush.
	postgres.restart().await;
	// A initiated A-B, so reconnect it without waiting for its periodic reconnect timer.
	sqlite_a
		.client()
		.connect_peer(ConnectPeerRequest {
			node_pubkey: postgres.node_id().to_string(),
			address: format!("127.0.0.1:{}", postgres.p2p_port),
			persist: true,
		})
		.await
		.unwrap();
	let restored_channels = wait_for_channels(&postgres, 2, TIMEOUT).await;
	for saved in saved_channels {
		let restored = restored_channels.iter().find(|c| c.channel_id == saved.channel_id).unwrap();
		assert_eq!(restored.user_channel_id, saved.user_channel_id);
		assert_eq!(restored.counterparty_node_id, saved.counterparty_node_id);
		assert_eq!(restored.funding_txo, saved.funding_txo);
		assert_eq!(restored.channel_value_sats, saved.channel_value_sats);
	}
	let restored_balances = open_channel_balances(&postgres, 2).await;
	assert_eq!(
		restored_balances.total_onchain_balance_sats,
		saved_balances.total_onchain_balance_sats
	);
	assert_eq!(channel_funds(&restored_balances), saved_channel_funds,
		"Channel funds changed across restart: before={saved_balances:?}, after={restored_balances:?}");
	assert_eq!(list_payments(&postgres).await, saved_payments);
	assert_eq!(wait_for_forwarded_payments(&postgres, 2, TIMEOUT).await, saved_forwards);
	let restored_stats = postgres
		.client()
		.list_channel_forwarding_stats(ListChannelForwardingStatsRequest { page_token: None })
		.await
		.unwrap();
	assert_eq!(restored_stats, saved_stats);
	let address_after = postgres.client().onchain_receive(OnchainReceiveRequest {}).await.unwrap();
	assert_ne!(first_address.address, address_after.address);
	assert_ne!(address_before.address, address_after.address);

	// Existing channels must still carry HTLCs in both directions after recovery.
	wait_for_channels(&sqlite_a, 1, TIMEOUT).await;
	wait_for_channels(&sqlite_c, 1, TIMEOUT).await;
	wait_for_gossip(&sqlite_a, 2, TIMEOUT).await;
	wait_for_gossip(&sqlite_c, 2, TIMEOUT).await;
	send_bolt11_payment(&sqlite_a, &sqlite_c, 20_000_000).await;
	send_bolt11_payment(&sqlite_c, &sqlite_a, 5_000_000).await;
	wait_for_forwarded_payments(&postgres, 4, TIMEOUT).await;

	let mut before_close = Vec::new();
	for server in [&sqlite_a, &postgres, &sqlite_c] {
		let balances = server.client().get_balances(GetBalancesRequest {}).await.unwrap();
		before_close.push((balances, list_payments(server).await));
	}

	// Close from each backend, and check both endpoints removed their channels.
	close_channel(&sqlite_a, &postgres, &channel_ab).await;
	close_channel(&postgres, &sqlite_c, &channel_bc).await;
	for server in [&sqlite_a, &postgres, &sqlite_c] {
		wait_for_channels(server, 0, TIMEOUT).await;
	}
	mine_and_sync(&bitcoind, &[&sqlite_a, &postgres, &sqlite_c], 6).await;
	let mut expected_cooperative_balances = Vec::new();
	for ((server, receipts), (balances_before, payments_before)) in
		[(&sqlite_a, 1), (&postgres, 2), (&sqlite_c, 1)].iter().zip(&before_close)
	{
		let expected = expected_onchain_balance(
			&bitcoind,
			server,
			balances_before.total_onchain_balance_sats,
			payments_before,
			*receipts,
			TIMEOUT,
		)
		.await;
		let recovered = wait_for_settled_balance(server, expected, TIMEOUT).await;
		assert_recovered_balance(balances_before, &recovered);
		expected_cooperative_balances.push(expected);
	}
	postgres.restart().await;
	wait_for_channels(&postgres, 0, TIMEOUT).await;
	wait_for_forwarded_payments(&postgres, 4, TIMEOUT).await;
	wait_for_settled_balance(&postgres, expected_cooperative_balances[1], TIMEOUT).await;

	// Put funds on both sides at channel creation so no HTLC settlement races with force-close.
	let force_channel = postgres
		.client()
		.open_channel(OpenChannelRequest {
			node_pubkey: sqlite_c.node_id().to_string(),
			address: format!("127.0.0.1:{}", sqlite_c.p2p_port),
			amount: Some(open_channel_request::Amount::ChannelAmountSats(1_000_000)),
			push_to_counterparty_msat: Some(50_000_000),
			channel_config: None,
			announce_channel: false,
			disable_counterparty_reserve: false,
		})
		.await
		.unwrap()
		.user_channel_id;
	wait_for_usable_channel(postgres.client(), &bitcoind, TIMEOUT).await;
	wait_for_channels(&sqlite_c, 1, TIMEOUT).await;
	let mut before_force_close = Vec::new();
	for server in [&postgres, &sqlite_c] {
		let balances = server.client().get_balances(GetBalancesRequest {}).await.unwrap();
		before_force_close.push((balances, list_payments(server).await));
	}
	// Have SQLite discover the unilateral close onchain, ensuring PostgreSQL's commitment
	// confirms without a competing commitment broadcast in response to a peer error message.
	// Clear both peer stores so neither side reconnects before the commitment confirms.
	postgres
		.client()
		.disconnect_peer(DisconnectPeerRequest { node_pubkey: sqlite_c.node_id().to_string() })
		.await
		.unwrap();
	sqlite_c
		.client()
		.disconnect_peer(DisconnectPeerRequest { node_pubkey: postgres.node_id().to_string() })
		.await
		.unwrap();
	postgres
		.client()
		.force_close_channel(ForceCloseChannelRequest {
			user_channel_id: force_channel,
			counterparty_node_id: sqlite_c.node_id().to_string(),
			force_close_reason: Some("PostgreSQL persistence e2e test".to_string()),
		})
		.await
		.unwrap();
	let force_claims = wait_for_force_close_claims(
		&bitcoind,
		&[
			(&postgres, BalanceSource::HolderForceClosed),
			(&sqlite_c, BalanceSource::CounterpartyForceClosed),
		],
		TIMEOUT,
	)
	.await;
	wait_for_channels(&postgres, 0, TIMEOUT).await;
	wait_for_channels(&sqlite_c, 0, TIMEOUT).await;

	// Recover persisted channel monitors while the force-close outputs are still timelocked.
	postgres.restart().await;
	let restored = postgres.client().get_balances(GetBalancesRequest {}).await.unwrap();
	assert_eq!(restored.lightning_balances.len(), 1);
	assert_eq!(
		restored.lightning_balances[0].balance_type,
		Some(lightning_balance::BalanceType::ClaimableAwaitingConfirmations(
			force_claims[0].clone()
		))
	);
	let maturity_height =
		force_claims.iter().map(|claim| u64::from(claim.confirmation_height)).max().unwrap();
	let height = postgres
		.client()
		.get_node_info(GetNodeInfoRequest {})
		.await
		.unwrap()
		.current_best_block
		.unwrap()
		.height as u64;
	mine_and_sync(&bitcoind, &[&postgres, &sqlite_c], maturity_height - height).await;

	// Confirm the sweeps and reconcile every wallet credit/debit, including any anchor-bump
	// fees, using only ldk-server's public payment and balance APIs.
	let mut expected_force_balances = Vec::new();
	for (server, (balances_before, payments_before)) in
		[&postgres, &sqlite_c].iter().zip(&before_force_close)
	{
		let expected = expected_onchain_balance(
			&bitcoind,
			server,
			balances_before.total_onchain_balance_sats,
			payments_before,
			1,
			TIMEOUT,
		)
		.await;
		let recovered = wait_for_settled_balance(server, expected, TIMEOUT).await;
		assert_recovered_balance(balances_before, &recovered);
		expected_force_balances.push(expected);
	}
	wait_for_settled_balance(&sqlite_a, expected_cooperative_balances[0], TIMEOUT).await;
	let closed_payments = list_payments(&postgres).await;
	postgres.restart().await;
	wait_for_channels(&postgres, 0, TIMEOUT).await;
	wait_for_forwarded_payments(&postgres, 4, TIMEOUT).await;
	wait_for_settled_balance(&postgres, expected_force_balances[0], TIMEOUT).await;
	assert_eq!(list_payments(&postgres).await, closed_payments);
}
