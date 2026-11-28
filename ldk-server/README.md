# ldk-server

The main LDK Server daemon. This is a Lightning Network node that exposes a gRPC API over
HTTP/2 with TLS, built on [LDK Node](https://github.com/lightningdevkit/ldk-node).

## Running

```bash
cargo run --release --bin ldk-server /path/to/config.toml
```

See the [Getting Started](../docs/getting-started.md) guide for a full walkthrough.

## Configuration

A fully annotated config template is provided at
[ldk-server-config.toml](../contrib/ldk-server-config.toml). See
[Configuration](../docs/configuration.md) for details on all options, environment variables,
and Bitcoin backend choices.

## Documentation

- [Getting Started](../docs/getting-started.md): build, configure, and run your first node
- [API Guide](../docs/api-guide.md): gRPC transport, authentication, and endpoint reference
- [Operations](../docs/operations.md): production deployment, backups, and monitoring

## Bounded wallet drain

`GetDrainInventory` and `BoundedDrain` are additive admin-only RPCs. The CLI
commands are `get-drain-inventory` and `bounded-drain`. Ordinary `OnchainSend`
behavior is unchanged. Neither RPC is available to the payment processor's
scoped credential.

Use these methods only after an external coordinator has persistently closed
Lightning listeners, removed remembered peers, and fenced channel/opening and
other value operations. Resolve existing claims and uncertain broadcasts first.
The node refuses observed channels, anchor reserves, monitor claims and tracked
sweeps. These observations do not acquire an atomic channel lifecycle lock.
Wallet inventory, transaction validation and signing use the wallet's existing
persister and wallet locks. A wallet update before lock acquisition changes the
commitment and causes refusal.

The inventory is complete or refused: at most 1,024 outputs and 81,920 encoded
inventory bytes. It conservatively refuses locked, unconfirmed, immature,
non-P2WPKH or incomplete outputs. Every response contains exact outpoints,
values, scripts, their total and a SHA-256 commitment. The commitment encodes
`LDKNode/BoundedDrainInventory/v1` followed by a NUL byte, a big-endian u32 input
count, then inputs sorted by Rust Bitcoin `OutPoint` order. Each entry encodes
the Bitcoin consensus outpoint, big-endian u64 value, big-endian u32 script
length and exact script bytes. Both RPC requests bind the expected public node
ID. Request bodies are limited to 1 KiB before protobuf decoding.

A drain requires the inventory commitment, exact destination and all three fee
fields: requested sat/vB, maximum sat/vB and maximum total fee in satoshis.
Before signing, the constructed transaction must use exactly the inventory and
one non-dust destination output. Its fee must meet both caps. The rate check
uses unsigned base weight as a conservative lower bound on signed weight. A
requested rate near the maximum can therefore refuse; use a lower requested
rate if needed. No fee estimator or ordinary-send fallback is used.

Persist the request in an external journal before one dispatch. The response
means successful local queue admission only, not successful broadcast or
confirmation. A failed or missing reply must be reconciled against exact inputs,
output, amount, fee, transaction ID and the node's existing on-chain payment
record. That record appears asynchronously through ordinary wallet events.
Do not repeat an unknown drain or replace its destination. A persistence or
queue error can leave the operation unresolved; this API does not provide
idempotent replay, signed-transaction export or automatic fee bumping.

The inventory count/byte limits bound the admitted result, not historical BDK graph or monitor traversal. The retirement coordinator must keep its original call/runtime budget; a timeout is an unknown operation and never authorizes an automatic retry.
