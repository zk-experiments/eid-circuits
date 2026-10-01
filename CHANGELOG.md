# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

- - -
## v0.8.2 - 2026-10-01
#### Build
- depend on noir-zk 0.3.3, refrozen as eid-circuits@0.8.2 - (d726102) - Anton Velichko
#### Continuous Integration
- (**packs**) retry the published-downloads check for up to 10 minutes - (aa5b198) - Anton Velichko
- (**release**) release a patch for build commits - (1e10225) - Anton Velichko

- - -

## v0.8.1 - 2026-09-30
#### Performance
- (**rsa**) 2-bit windowed exponentiation, 9-20% fewer gates in every RSA step - (67d9bf7) - Anton Velichko
#### Continuous Integration
- (**packs**) retry the published-downloads check while the cdn catches up - (2b472ba) - Anton Velichko
- (**release**) release a patch for perf commits - (cad7d44) - Anton Velichko
#### Miscellaneous Chores
- add noir-lang's noir-idioms and noir-optimize-acir skills - (3ee9db3) - Anton Velichko

- - -

## v0.8.0 - 2026-09-29
#### Features
- <span style="background-color: #d73a49; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 0.85em;">BREAKING</span>(**circuits**) eid-circuits as the identity layer on noir-zk's layered registries - (e5c8a44) - Anton Velichko
#### Documentation
- (**bench**) re-measure the benchmarks with Noir rc.3 and bb 7 - (30801ae) - Anton Velichko
- the identity layer - (30b236f) - Anton Velichko
- fix the v0.7.0 review findings - (8b73f39) - Anton Velichko
#### Build system
- depend on noir-zk 0.3.0 from crates.io - (367b651) - Anton Velichko
#### Continuous Integration
- (**fold**) compile the chains' circuits before folding them - (a0a9cce) - Anton Velichko
- fold the sample chains through noir-zk's kernels in-process - (c447817) - Anton Velichko
- keep release and nightly runs alive, and check the published packs - (71a43f2) - Anton Velichko
#### Refactoring
- (**steps**) derive the flatten offsets from VIEWERS - (90a3f36) - Anton Velichko

- - -

## v0.7.0 - 2026-09-28
#### Features
- <span style="background-color: #d73a49; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 0.85em;">BREAKING</span>(**kernel**) drop the public SHA-1 flag and the steps' hash ids - (669c70b) - Anton Velichko

- - -

## v0.6.0 - 2026-09-28
#### Features
- <span style="background-color: #d73a49; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 0.85em;">BREAKING</span>(**envelope**) seal the envelope to one viewer key, the receiver's - (94f1ac0) - Anton Velichko

- - -

## v0.5.0 - 2026-09-28
#### Features
- <span style="background-color: #d73a49; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 0.85em;">BREAKING</span>(**envelope**) add a scoped nullifier for Sybil resistance - (67fc858) - Anton Velichko

- - -

## v0.4.2 - 2026-09-28
#### Bug Fixes
- (**ci**) provision the SRS noir-zk pins before freezing - (7f8f99a) - Anton Velichko

- - -

## v0.4.1 - 2026-09-27
#### Bug Fixes
- (**ci**) read R2_ACCOUNT_ID from a variable or a secret - (a72edc8) - Anton Velichko

- - -

## v0.4.0 - 2026-09-27
#### Features
- (**eid-circuits**) bundled feature compiles circuits at build time - (fe4fb35) - Anton Velichko
- (**eid-vectors**) per-country circuit packs - (b0dd0a0) - Anton Velichko
- pin verification keys and link releases to their packs - (d17bc8d) - Anton Velichko
- circuit packs per key family, published per release - (cb1ad5f) - Anton Velichko
#### Documentation
- (**audit**) the noir_bigcurve MSM hint warning is a reviewed false positive - (d6c8eba) - Anton Velichko
#### Build system
- use noir-zk 0.2.1 from crates.io - (a652b43) - Anton Velichko
#### Continuous Integration
- upload packs to R2 through its S3 API - (76fcce7) - Anton Velichko
- publish circuit packs on every release - (e5e0c9d) - Anton Velichko

- - -

## v0.3.0 - 2026-09-27
#### Features
- (**eid-zk**) prove and verify documents through noir-zk with frozen circuits - (6571709) - Anton Velichko
#### Bug Fixes
- (**eid-circuits**) frozen vk-tree.json names noir-zk freeze as its writer - (3e895cf) - Anton Velichko
#### Build system
- pin noir-zk 3b4d534 - (022ad46) - Anton Velichko
- <span style="background-color: #d73a49; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 0.85em;">BREAKING</span>move to Noir 1.0.0-rc.3 and bb 7.0.0-nightly.20260927 - (daf89f8) - Anton Velichko
#### Continuous Integration
- fetch noir-zk anonymously now that it is public - (9b5266d) - Anton Velichko
- fetch the private noir-zk and install libc++ for bb - (b8211e6) - Anton Velichko
#### Refactoring
- (**eid-circuits**) record proof system and Chonk role per circuit - (9752f4e) - Anton Velichko
- (**eid-circuits**) fold wrapped apps (KernelX::select / wrap) - (6a19250) - Anton Velichko
- (**eid-circuits**) typed bindings for noir-zk's folding backend - (1205ac3) - Anton Velichko
- rename eid-zk to the eid-circuits crate - (d680320) - Anton Velichko

- - -

## v0.2.0 - 2026-09-27
#### Features
- (**folding**) keep proven chains' proof, vk and public outputs with fold.py --out - (2d790fe) - Anton Velichko
- <span style="background-color: #d73a49; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 0.85em;">BREAKING</span>(**folding**) fold the three steps into one Chonk proof - (bef327f) - Anton Velichko
- (**prover**) build the inputs of all three steps from a document - (ce411e9) - Anton Velichko
- (**prover**) select the step circuits from a document's NFC data - (3e7967a) - Anton Velichko
#### Miscellaneous Chores
- use csca-registry v0.3.1 and update the audit notes - (1c8c5cb) - Anton Velichko

- - -

## v0.1.0 - 2026-09-27
#### Features
- (**der**) add constrained DER reading for TBSCertificates - (a6d9ea3) - Anton Velichko
- (**dsc**) add the DSC step circuits and a per-country cost report - (096e258) - Anton Velichko
- <span style="background-color: #d73a49; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 0.85em;">BREAKING</span>(**envelope**) carry DG1 only - (5ef5910) - Anton Velichko
- (**envelope**) bind the envelope to a public context and verify steps separately - (1a18d59) - Anton Velichko
- (**envelope**) add the envelope step circuits and encryption - (4e8fb3c) - Anton Velichko
- (**sod**) add the SOD step circuits - (ee058f6) - Anton Velichko
- add ECDSA library, benchmark circuits and size and coverage reports - (d66f09a) - Anton Velichko
- add hash and RSA libraries with real-certificate vectors - (a5114c0) - Anton Velichko
#### Performance Improvements
- (**hash**) use zac-williamson/sha1 for SHA-1 - (903bb78) - Anton Velichko
#### Documentation
- describe a DSC registry and caching step A as future improvements - (f9236be) - Anton Velichko
#### Continuous Integration
- check committed circuit sizes instead of compiling every circuit - (7adcea5) - Anton Velichko
- cap proving memory at 2 GiB - (5b475f4) - Anton Velichko
- let the path filter read pull request files - (1561446) - Anton Velichko
- fetch the now-public csca-registry over https - (7ee8f8e) - Anton Velichko
#### Miscellaneous Chores
- initialize repository - (23a9072) - Anton Velichko

- - -

Changelog generated by [cocogitto](https://github.com/cocogitto/cocogitto).