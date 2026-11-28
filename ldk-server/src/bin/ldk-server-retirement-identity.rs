// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Fixed offline signet public identity. No daemon, configuration, database or network.
//! The host must supply the exact version-pinned candidate mnemonic through a private pipe
//! and enforce its original deadline. Neither this output nor a CLI invocation grants send
//! or initialization authority. Failure output is fixed and never contains input material.

use std::io::{self, Read, Write};
use std::str::FromStr;

use ldk_node::bip39::Mnemonic;
use ldk_node::entropy::NodeEntropy;

const MAX_INPUT: usize = 256;

fn reply(raw: &[u8]) -> Result<String, ()> {
	if raw.is_empty() || raw.len() > MAX_INPUT || !raw.ends_with(b"\n") {
		return Err(());
	}
	let text = std::str::from_utf8(&raw[..raw.len() - 1]).map_err(|_| ())?;
	// One canonical English BIP39 phrase, with no passphrase or alternate selector.
	if text.is_empty()
		|| !text.bytes().all(|b| b.is_ascii_lowercase() || b == b' ')
		|| text.starts_with(' ')
		|| text.ends_with(' ')
		|| text.contains("  ")
	{
		return Err(());
	}
	let mnemonic = Mnemonic::from_str(text).map_err(|_| ())?;
	let identity =
		ldk_node::retirement_identity::signet(&NodeEntropy::from_bip39_mnemonic(mnemonic, None))
			.map_err(|_| ())?;
	let script = identity.address.script_pubkey();
	Ok(format!("{{\"format_version\":1,\"network\":\"signet\",\"node_id\":\"{}\",\"external_index\":0,\"address\":\"{}\",\"script_pubkey\":\"{}\"}}\n",
        identity.node_id, identity.address, script.to_hex_string()))
}

fn run() -> Result<(), ()> {
	if std::env::args_os().len() != 1 {
		return Err(());
	}
	let mut raw = Vec::new();
	io::stdin().lock().take((MAX_INPUT + 1) as u64).read_to_end(&mut raw).map_err(|_| ())?;
	let output = reply(&raw)?;
	io::stdout().lock().write_all(output.as_bytes()).map_err(|_| ())
}

fn main() {
	// A dependency panic must not format a seed-bearing error to stderr.
	std::panic::set_hook(Box::new(|_| {}));
	if std::panic::catch_unwind(run).ok() != Some(Ok(())) {
		let _ = io::stderr().write_all(b"LDK_RETIREMENT_IDENTITY_REFUSED\n");
		std::process::exit(1);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n";

	#[test]
	fn fixed_public_shape_is_deterministic_and_contains_no_mnemonic() {
		let output = reply(PHRASE.as_bytes()).unwrap();
		assert_eq!(output, reply(PHRASE.as_bytes()).unwrap());
		assert!(output.starts_with("{\"format_version\":1,\"network\":\"signet\",\"node_id\":\"0"));
		assert!(output.contains("\"external_index\":0,\"address\":\"tb1q"));
		assert!(output.contains("\"script_pubkey\":\"0014"));
		assert!(!output.contains("abandon"));
		assert!(output.len() < 512);
	}

	#[test]
	fn missing_extra_noncanonical_or_invalid_secret_input_refuses() {
		for raw in [
			b"".to_vec(),
			PHRASE.trim_end().as_bytes().to_vec(),
			format!("{}{}", PHRASE, PHRASE).into_bytes(),
			format!(" {}", PHRASE).into_bytes(),
			PHRASE.replace(' ', "  ").into_bytes(),
			b"not a mnemonic\n".to_vec(),
			vec![b'a'; MAX_INPUT + 1],
			vec![255, b'\n'],
		] {
			assert!(reply(&raw).is_err());
		}
	}
}
