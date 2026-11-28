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

// The ordinary private-pipe mode above is deliberately unchanged. These two fixed
// modes are only for the disposable O1 peer's isolated, host-owned data mount.
fn dispatch() -> Result<(), ()> {
	let args: Vec<_> = std::env::args_os().collect();
	if args.len() == 1 {
		return run();
	}
	#[cfg(target_os = "linux")]
	if args.len() == 2 {
		let create = if args[1] == "--create-o1-peer-seed" {
			true
		} else if args[1] == "--observe-o1-peer-seed" {
			false
		} else {
			return Err(());
		};
		let output = peer_seed::run(create)?;
		return io::stdout().lock().write_all(output.as_bytes()).map_err(|_| ());
	}
	Err(())
}

#[cfg(target_os = "linux")]
mod peer_seed {
	use super::{reply, Mnemonic, MAX_INPUT};
	use std::fs::{self, File, Metadata, OpenOptions};
	use std::io::{Read, Write};
	use std::os::fd::AsRawFd;
	use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
	use std::path::{Path, PathBuf};

	// Linux flags; no new dependency or unsafe system-call wrapper is needed.
	const NOFOLLOW: i32 = 0x20000;
	const DIRECTORY: i32 = 0x10000;
	const NONBLOCK: i32 = 0x800;
	const OWNER: u32 = 65532;
	const INTENT: &str = ".o1-peer-seed-intent";
	const SEED: &str = "keys_mnemonic";
	const COMPLETE: &str = ".o1-peer-seed-complete";
	const INTENT_BYTES: &[u8] = b"LDK_O1_PEER_SEED_INTENT_V1\n";
	const COMPLETE_BYTES: &[u8] = b"LDK_O1_PEER_SEED_COMPLETE_V1\n";

	struct Directory {
		file: File,
		parent: File,
		name: String,
		uid: u32,
		gid: u32,
	}

	fn relative(dir: &File, name: &str) -> PathBuf {
		PathBuf::from(format!("/proc/self/fd/{}/{}", dir.as_raw_fd(), name))
	}

	fn same(left: &Metadata, right: &Metadata) -> bool {
		left.dev() == right.dev() && left.ino() == right.ino()
	}

	fn directory(path: &Path) -> Result<File, ()> {
		OpenOptions::new()
			.read(true)
			.custom_flags(NOFOLLOW | DIRECTORY | NONBLOCK)
			.open(path)
			.map_err(|_| ())
	}

	fn ancestor(path: &Path) -> Result<File, ()> {
		let file = directory(path)?;
		let meta = file.metadata().map_err(|_| ())?;
		if !meta.is_dir() || meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o022 != 0 {
			return Err(());
		}
		Ok(file)
	}

	impl Directory {
		fn fixed() -> Result<Self, ()> {
			// Walk each fixed ancestor via held descriptors; a symlink in /var or
			// /var/lib must not redirect the seed operation outside the mount.
			let root = ancestor(Path::new("/"))?;
			let var = ancestor(&relative(&root, "var"))?;
			let parent = ancestor(&relative(&var, "lib"))?;
			Self::open(parent, "ldk-server", OWNER, OWNER)
		}

		fn open(parent: File, name: &str, uid: u32, gid: u32) -> Result<Self, ()> {
			let file = directory(&relative(&parent, name))?;
			let result = Self { file, parent, name: name.to_owned(), uid, gid };
			result.validate()?;
			Ok(result)
		}

		fn validate(&self) -> Result<(), ()> {
			let opened = self.file.metadata().map_err(|_| ())?;
			let named = fs::symlink_metadata(relative(&self.parent, &self.name)).map_err(|_| ())?;
			if !opened.is_dir()
				|| !named.is_dir()
				|| !same(&opened, &named)
				|| opened.uid() != self.uid
				|| opened.gid() != self.gid
				|| opened.mode() & 0o7777 != 0o700
			{
				return Err(());
			}
			Ok(())
		}

		fn checked_file(&self, file: &File, name: &str, length: u64) -> Result<(), ()> {
			self.validate()?;
			let opened = file.metadata().map_err(|_| ())?;
			let named = fs::symlink_metadata(relative(&self.file, name)).map_err(|_| ())?;
			if !opened.is_file()
				|| !named.is_file()
				|| !same(&opened, &named)
				|| opened.uid() != self.uid
				|| opened.gid() != self.gid
				|| opened.nlink() != 1
				|| opened.mode() & 0o7777 != 0o600
				|| opened.len() != length
			{
				return Err(());
			}
			Ok(())
		}

		fn absent(&self, name: &str) -> Result<(), ()> {
			self.validate()?;
			match fs::symlink_metadata(relative(&self.file, name)) {
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
				_ => Err(()),
			}
		}

		fn write_once(&self, name: &str, data: &[u8]) -> Result<(), ()> {
			self.validate()?;
			let mut file = OpenOptions::new()
				.write(true)
				.create_new(true)
				.mode(0o600)
				.custom_flags(NOFOLLOW | NONBLOCK)
				.open(relative(&self.file, name))
				.map_err(|_| ())?;
			self.checked_file(&file, name, 0)?;
			file.write_all(data).map_err(|_| ())?;
			file.sync_all().map_err(|_| ())?;
			self.checked_file(&file, name, data.len() as u64)?;
			self.file.sync_all().map_err(|_| ())?;
			self.validate()
		}

		fn read(&self, name: &str, cap: usize) -> Result<Vec<u8>, ()> {
			self.validate()?;
			let mut file = OpenOptions::new()
				.read(true)
				.custom_flags(NOFOLLOW | NONBLOCK)
				.open(relative(&self.file, name))
				.map_err(|_| ())?;
			let before = file.metadata().map_err(|_| ())?;
			if before.len() == 0 || before.len() > cap as u64 {
				return Err(());
			}
			self.checked_file(&file, name, before.len())?;
			let mut raw = Vec::with_capacity(before.len() as usize);
			(&mut file).take((cap + 1) as u64).read_to_end(&mut raw).map_err(|_| ())?;
			self.checked_file(&file, name, before.len())?;
			let after = file.metadata().map_err(|_| ())?;
			if raw.len() as u64 != before.len()
				|| before.mtime() != after.mtime()
				|| before.mtime_nsec() != after.mtime_nsec()
				|| before.ctime() != after.ctime()
				|| before.ctime_nsec() != after.ctime_nsec()
			{
				return Err(());
			}
			Ok(raw)
		}

		fn observe(&self) -> Result<String, ()> {
			if self.read(INTENT, INTENT_BYTES.len())? != INTENT_BYTES
				|| self.read(COMPLETE, COMPLETE_BYTES.len())? != COMPLETE_BYTES
			{
				return Err(());
			}
			let seed = self.read(SEED, MAX_INPUT)?;
			// O1 creates exactly 256 entropy bits. The ordinary pipe mode still
			// accepts every valid BIP39 length; a peer record must be 24 words.
			if seed.split(|byte| *byte == b' ').count() != 24 {
				return Err(());
			}
			let output = reply(&seed)?;
			self.validate()?;
			Ok(output)
		}

		fn create(
			&self, entropy: impl FnOnce(&mut [u8; 32]) -> Result<(), ()>,
		) -> Result<String, ()> {
			for name in [INTENT, SEED, COMPLETE] {
				self.absent(name)?;
			}
			// Intent and its directory entry are durable BEFORE entropy is sampled.
			// An incomplete attempt is retained. There is deliberately no rollback,
			// overwrite, regeneration or retry of any uncertain creation operation.
			self.write_once(INTENT, INTENT_BYTES)?;
			let mut bytes = [0u8; 32];
			entropy(&mut bytes)?;
			let phrase = format!("{}\n", Mnemonic::from_entropy(&bytes).map_err(|_| ())?);
			let output = reply(phrase.as_bytes())?;
			self.write_once(SEED, phrase.as_bytes())?;
			// A separate marker distinguishes a fully synced seed from a process
			// killed during writing. Observation cannot repair a partial attempt.
			self.write_once(COMPLETE, COMPLETE_BYTES)?;
			if self.observe()? != output {
				return Err(());
			}
			Ok(output)
		}
	}

	pub(super) fn run(create: bool) -> Result<String, ()> {
		let dir = Directory::fixed()?;
		if create {
			dir.create(fill_entropy)
		} else {
			dir.observe()
		}
	}

	fn fill_entropy(bytes: &mut [u8; 32]) -> Result<(), ()> {
		getrandom::getrandom(bytes).map_err(|_| ())
	}

	#[cfg(test)]
	mod tests {
		use super::*;
		use std::os::unix::fs::{symlink, PermissionsExt};
		use std::sync::atomic::{AtomicU64, Ordering};
		static NEXT: AtomicU64 = AtomicU64::new(0);
		const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n";

		struct Fixture {
			path: PathBuf,
			dir: Directory,
		}
		impl Fixture {
			fn new() -> Self {
				let path = std::env::temp_dir().join(format!(
					"o1-peer-seed-{}-{}-{}",
					std::process::id(),
					std::time::SystemTime::now()
						.duration_since(std::time::UNIX_EPOCH)
						.unwrap()
						.as_nanos(),
					NEXT.fetch_add(1, Ordering::Relaxed)
				));
				fs::create_dir(&path).unwrap();
				fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
				let meta = fs::metadata(&path).unwrap();
				let parent = directory(path.parent().unwrap()).unwrap();
				let dir = Directory::open(
					parent,
					path.file_name().unwrap().to_str().unwrap(),
					meta.uid(),
					meta.gid(),
				)
				.unwrap();
				Self { path, dir }
			}
		}
		impl Drop for Fixture {
			fn drop(&mut self) {
				let _ = fs::remove_dir_all(&self.path);
			}
		}

		fn deterministic(bytes: &mut [u8; 32]) -> Result<(), ()> {
			bytes.fill(0);
			Ok(())
		}

		#[test]
		fn lost_public_reply_resolves_read_only_without_regeneration() {
			let fixture = Fixture::new();
			let lost = fixture.dir.create(deterministic).unwrap();
			assert_eq!(fixture.dir.observe().unwrap(), lost);
			assert!(!lost.contains("abandon"));
			assert!(fixture.dir.create(|_| panic!("entropy must not be sampled twice")).is_err());
			assert_eq!(fixture.dir.observe().unwrap(), lost);
		}

		#[test]
		fn valid_twelve_word_seed_with_complete_markers_is_not_an_o1_seed() {
			let fixture = Fixture::new();
			fixture.dir.write_once(INTENT, INTENT_BYTES).unwrap();
			fixture.dir.write_once(SEED, PHRASE.as_bytes()).unwrap();
			fixture.dir.write_once(COMPLETE, COMPLETE_BYTES).unwrap();
			assert!(fixture.dir.observe().is_err());
		}

		#[test]
		fn production_entropy_creates_distinct_private_twenty_four_word_seeds() {
			let first = Fixture::new();
			let second = Fixture::new();
			let a = first.dir.create(fill_entropy).unwrap();
			let b = second.dir.create(fill_entropy).unwrap();
			assert_ne!(a, b);
			for (fixture, output) in [(&first, a), (&second, b)] {
				let seed = fixture.dir.read(SEED, MAX_INPUT).unwrap();
				assert_eq!(seed.split(|byte| *byte == b' ').count(), 24);
				let phrase = std::str::from_utf8(&seed).unwrap().trim_end();
				assert!(!output.contains(phrase));
				assert_eq!(fixture.dir.observe().unwrap(), output);
			}
		}

		#[test]
		fn intent_is_durable_before_entropy_and_failure_never_retries() {
			let fixture = Fixture::new();
			assert!(fixture
				.dir
				.create(|_| {
					assert_eq!(fixture.dir.read(INTENT, INTENT_BYTES.len()).unwrap(), INTENT_BYTES);
					assert!(!fixture.path.join(SEED).exists());
					Err(())
				})
				.is_err());
			assert!(fixture.dir.observe().is_err());
			assert!(fixture.dir.create(|_| panic!("must not regenerate")).is_err());
		}

		#[test]
		fn interrupted_seed_or_completion_write_cannot_be_observed_or_retried() {
			for completed_seed in [false, true] {
				let fixture = Fixture::new();
				fixture.dir.write_once(INTENT, INTENT_BYTES).unwrap();
				let seed = if completed_seed { PHRASE.as_bytes() } else { b"abandon" };
				fixture.dir.write_once(SEED, seed).unwrap();
				if completed_seed {
					fixture.dir.write_once(COMPLETE, b"LDK_").unwrap();
				}
				assert!(fixture.dir.observe().is_err());
				assert!(fixture.dir.create(|_| panic!("must not regenerate")).is_err());
			}
		}

		#[test]
		fn unexpected_existing_seed_without_intent_is_never_adopted() {
			let fixture = Fixture::new();
			fixture.dir.write_once(SEED, PHRASE.as_bytes()).unwrap();
			assert!(fixture.dir.observe().is_err());
			assert!(fixture.dir.create(|_| panic!("must not generate")).is_err());
			assert!(!fixture.path.join(INTENT).exists());
		}

		#[test]
		fn symlinks_hardlinks_wrong_modes_and_wrong_owner_refuse() {
			let fixture = Fixture::new();
			fixture.dir.create(deterministic).unwrap();
			let seed = fixture.path.join(SEED);
			fs::hard_link(&seed, fixture.path.join("duplicate")).unwrap();
			assert!(fixture.dir.observe().is_err());
			fs::remove_file(fixture.path.join("duplicate")).unwrap();
			fs::set_permissions(&seed, fs::Permissions::from_mode(0o640)).unwrap();
			assert!(fixture.dir.observe().is_err());
			fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).unwrap();
			fs::rename(&seed, fixture.path.join("saved")).unwrap();
			symlink("saved", &seed).unwrap();
			assert!(fixture.dir.observe().is_err());
			let parent = directory(fixture.path.parent().unwrap()).unwrap();
			assert!(Directory::open(
				parent,
				&fixture.dir.name,
				fixture.dir.uid ^ 1,
				fixture.dir.gid
			)
			.is_err());
		}

		#[test]
		fn directory_replacement_is_not_followed() {
			let fixture = Fixture::new();
			fixture.dir.create(deterministic).unwrap();
			let moved = fixture.path.with_extension("moved");
			fs::rename(&fixture.path, &moved).unwrap();
			fs::create_dir(&fixture.path).unwrap();
			fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o700)).unwrap();
			assert!(fixture.dir.observe().is_err());
			assert!(fixture.dir.create(|_| panic!("must not generate")).is_err());
			fs::remove_dir_all(moved).unwrap();
		}
	}
}

fn main() {
	// A dependency panic must not format a seed-bearing error to stderr.
	std::panic::set_hook(Box::new(|_| {}));
	if std::panic::catch_unwind(dispatch).ok() != Some(Ok(())) {
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
