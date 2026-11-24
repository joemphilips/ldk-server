// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use std::io;
use std::path::Path;
use std::str::FromStr;

use ldk_node::bip39::Mnemonic;
use ldk_node::entropy::NodeEntropy;

use crate::util::read_to_string_with_limit;

const DEFAULT_MNEMONIC_FILE: &str = "keys_mnemonic";
const MNEMONIC_FILE_SIZE_LIMIT: usize = 1024;

/// Reads the node mnemonic. It never creates one: a missing file can be a missing mount or a wrong
/// storage directory of an existing node, and a new mnemonic is a node with another identity.
pub(crate) fn load_node_entropy(storage_dir: &Path) -> io::Result<NodeEntropy> {
	let mnemonic_path = storage_dir.join(DEFAULT_MNEMONIC_FILE);

	let raw = read_to_string_with_limit(&mnemonic_path, MNEMONIC_FILE_SIZE_LIMIT).map_err(|e| {
		if e.kind() == io::ErrorKind::NotFound {
			io::Error::new(
				io::ErrorKind::NotFound,
				format!(
					"Refusing to start: the node mnemonic file {} is missing. ldk-server does not \
					 create it. Write the BIP39 mnemonic of this node to it before the start. The \
					 first start of a new node needs a new mnemonic there.",
					mnemonic_path.display()
				),
			)
		} else {
			e
		}
	})?;
	let mnemonic = Mnemonic::from_str(raw.trim()).map_err(|e| {
		io::Error::new(
			io::ErrorKind::InvalidData,
			format!("Invalid BIP39 mnemonic in {}: {}", mnemonic_path.display(), e),
		)
	})?;

	Ok(NodeEntropy::from_bip39_mnemonic(mnemonic, None))
}

#[cfg(test)]
mod tests {
	use std::fs;
	use std::path::PathBuf;

	use super::*;

	const STALE_SEED_FILE: &str = "keys_seed";
	const KNOWN_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

	fn tempdir(tag: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!(
			"ldk-server-entropy-test-{}-{}",
			tag,
			std::process::id()
		));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		dir
	}

	#[test]
	fn refuses_a_missing_mnemonic_file() {
		let dir = tempdir("missing");

		let err = load_node_entropy(&dir).unwrap_err();

		assert_eq!(err.kind(), io::ErrorKind::NotFound);
		let path = dir.join(DEFAULT_MNEMONIC_FILE);
		assert!(err.to_string().contains(path.to_str().unwrap()), "{err}");
		assert_eq!(fs::read_dir(&dir).unwrap().count(), 0, "a refused start created a file");
	}

	#[test]
	fn refuses_a_missing_storage_directory() {
		let dir = tempdir("no-storage").join("storage");

		let err = load_node_entropy(&dir).unwrap_err();

		assert_eq!(err.kind(), io::ErrorKind::NotFound);
		assert!(!dir.exists(), "a refused start created the storage directory");
	}

	#[test]
	fn rereads_existing_mnemonic_without_mutation() {
		let dir = tempdir("reread");
		let mnemonic_path = dir.join(DEFAULT_MNEMONIC_FILE);
		fs::write(&mnemonic_path, format!("{}\n", KNOWN_MNEMONIC)).unwrap();
		let bytes_before = fs::read(&mnemonic_path).unwrap();

		load_node_entropy(&dir).unwrap();

		let bytes_after = fs::read(&mnemonic_path).unwrap();
		assert_eq!(bytes_before, bytes_after, "mnemonic file content changed");
	}

	#[test]
	fn a_stale_keys_seed_does_not_replace_the_mnemonic() {
		let dir = tempdir("stale-seed");
		let stale_seed_path = dir.join(STALE_SEED_FILE);
		fs::write(&stale_seed_path, vec![0x42u8; 64]).unwrap();

		let err = load_node_entropy(&dir).unwrap_err();

		assert_eq!(err.kind(), io::ErrorKind::NotFound);
		assert!(stale_seed_path.exists(), "stale keys_seed was removed");
	}

	#[test]
	fn rejects_invalid_mnemonic_file() {
		let dir = tempdir("invalid");
		fs::write(
			dir.join(DEFAULT_MNEMONIC_FILE),
			"these words are definitely not a valid bip39 phrase at all nope",
		)
		.unwrap();

		let err = load_node_entropy(&dir).unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	}

	#[test]
	fn rejects_oversized_mnemonic_file() {
		let dir = tempdir("oversized");
		fs::write(dir.join(DEFAULT_MNEMONIC_FILE), vec![b'a'; MNEMONIC_FILE_SIZE_LIMIT + 1])
			.unwrap();

		let err = load_node_entropy(&dir).unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	}
}
