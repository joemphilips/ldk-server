// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! LDK Node bundles SQLite through `libsqlite3-sys` 0.28.0, which RUSTSEC-2026-0459 affects. The
//! `[patch.crates-io]` section replaces it with a copy that has the upstream correction. Cargo
//! applies a patch only from the root workspace of a build, and ignores one that no longer matches
//! a version, so check the lock file of each build that links the library.

const BACKPORT: &str = "source = \"git+https://github.com/joemphilips/cdk?\
	rev=fee0f9d4d63b4d121c608b6e43e407e4b080d50e#fee0f9d4d63b4d121c608b6e43e407e4b080d50e\"";

#[test]
fn each_build_locks_the_sqlite_source_with_the_backport() {
	for (name, lock) in [
		("Cargo.lock", include_str!("../../Cargo.lock")),
		("e2e-tests/Cargo.lock", include_str!("../../e2e-tests/Cargo.lock")),
	] {
		let packages: Vec<_> = lock
			.split("[[package]]")
			.filter(|package| package.contains("name = \"libsqlite3-sys\"\n"))
			.collect();
		assert_eq!(packages.len(), 1, "{name} must lock one libsqlite3-sys");
		assert!(packages[0].contains(BACKPORT), "{name}: {}", packages[0]);
	}
}
