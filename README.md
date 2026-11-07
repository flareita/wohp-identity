
# WOHP Identity

**WOHP Identity** is the private identity and deduplication service of the WOHP protocol: one person, one private profile, and a stable pairwise subject for each registered relying party. It does not depend on any relying party.

This repository contains the first Rust implementation of the *internal identity layer* described in the WOHP Technical Implementation Draft v1.0.1. 
It provides a small SDK-independent Rust API, persistent human bindings and an in-process development-only identity provider.

**It is not an EUDI verifier or an authentication server.** No EUDI SDK, OpenID Connect server, WebAuthn ceremony or production identity HTTP endpoint has been implemented. The optional loopback QR spike only delegates a presentation to an external verifier. The mock creates fixture evidence, not certified identity. Production configuration rejects the mock provider, production enrollment must wait for an approved EUDI (or selected notified eIDAS) adapter and maintained protocol implementations.

## Components and boundaries

| Path | Responsibility |
| --- | --- |
| `crates/wohp-api` | Stable versioned internal Rust source API: `IdentityProvider` (upstream adapter), `IdentityService` (application operations), bounded and redacted identity types. Zero external dependencies. |
| `crates/wohp` | Identity application core: challenges, deduplication, persistent subjects, status, revocation and recovery epochs, using SQLite, HMAC-SHA256 and OS-backed randomness. |
| `crates/wohp-mock` | In-process fixture provider implementing `IdentityProvider`, no EUDI SDK and no production assurance. |
| `crates/wohp-eudi` | EUDI Verifier Endpoint adapter implementing `IdentityProvider`: sync HTTP, SD-JWT nonce/audience validation, sandbox matching rule, UTC age thresholds. mdoc only behind an explicit opt-in. Development evidence only. |
| `crates/wohp/src/bin/wohp-mock.rs` | Privileged **local simulation CLI**, built only with the `mock` feature. It has no network listener or authenticated user interface. |
| `crates/wohp/tests/identity.rs` | Integration tests for persistence, concurrency, replay, expiry, recovery and environment separation. |

The adapter boundary is intentionally narrow:

```text
EUDI SDK / approved matching service   (future adapter)
                   |  validate issuer, signature, holder,
                   |  audience, nonce, status and person matching
                   v
       wohp_api::IdentityProvider
                   |  VerificationOutcome::Established(VerifiedPerson)
                   |  or Ambiguous / InvalidEvidence / Unavailable
                   v
          wohp::Service  <----> private SQLite database
                   |
                   v
       wohp_api::IdentityService
                   |  Rust DTOs, NOT OIDC tokens
                   v
       relying-party adapters            (registered clients)

Development: wohp_mock::MockIdentityProvider replaces the EUDI adapter.
```

No EUDI, HTTP, OIDC or WebAuthn SDK types enter `wohp-api`. A future EUDI adapter must convert verified protocol data to `CanonicalPerson` and
`VerifiedPerson` only after unambiguous person matching, credential serial numbers, wallet keys and an empty lookup are not person-level
identifiers. Errors crossing the interface have bounded, non-sensitive categories. Presentations, canonical references and subjects redact their
`Debug` representation. 

## Implemented identity behavior

1. `begin(Enrollment | Recovery { subject })` creates a random challenge and  nonce bound to a configured audience and five-minute lifetime. Calling recovery is a trusted internal action, a future transport adapter must authenticate and authorize the caller and recovery request first.
2. `complete(challenge_id, presentation)` consumes the challenge exactly once before provider verification. Failed/ambiguous/unavailable attempts consume the challenge, try again with a new one. Evidence is checked again by the core for context, class, policy, time and, when the  verification belongs to a registered client, that client's inclusive  minimum age.
3. An established canonical reference is stored only as a private HMAC lookup. SQLite transactions and uniqueness constraints serialize concurrent enrollment. Matching an existing reference returns `ExistingRequiresAuthentication`: it does not authenticate the user, refresh expired evidence, clear revocation or create a second human.
4. A new human receives one private persisted random 256-bit profile subject.
After explicit client registration and user authorization, each relying party receives a distinct persisted random 256-bit client subject (unpadded base64url). Neither is an EHID or bearer token, a client subject cannot be used to correlate the person at another client.
5. `status` returns `Valid`, `RevalidationRequired` or `Revoked`, an optional age threshold and an authentication epoch. Evidence expiry stays internal, and HTTP clients receive age validity only to the UTC day. `revoke` blocks the binding and increments that epoch. Successful authorized recovery preserves the subject and increments the epoch again. `validate_epoch` checks current state after a separate trusted authentication adapter    has authenticated the human, knowing the subject/epoch is not login.

The service stores its environment, provider  integration ID, evidence class, policy version, audience and lookup-key identity in the database. Reopening it under a changed identity  configuration fails rather than silently resetting deduplication. Each registered client has its own minimum age, stored with the client and audited when it changes. Mock evidence is rejected by a production-configured service, including when an adapter mislabels itself as production. Trustworthy production verification still depends on using a genuinely approved provider implementation.

Relying parties are registered from configuration (`WOHP_CLIENT_*` or `WOHP_CLIENTS_FILE`) otherwise only by the privileged `Service::register_client` operation, then receive stable pairwise subjects through `Service::client_subject` after adapter-level authentication and consent. The core is deliberately not an OIDC server: redirect URIs,
credentials, consent and protocol validation stay in its maintained adapter.

SQLite uses WAL, full synchronous writes, foreign keys, restricted schema values, parameterized statements and transactions. On Unix, new database
files are created with mode `0600`, and reopening a symlink or a file accessible to group/others is rejected. Operate it in a private directory, protect the lookup key, backups and database together. The demo CLI writes a raw 32-byte key file with mode `0600` on Unix and refuses broader key permissions. Loss of the lookup key would prevent recognizing existing people, this prototype does not implement key migration. Raw evidence retention, erasure policy and EUDI regulatory matching logs are not yet implemented.

## Backup and restore

`wohp-server` has two operator commands on the identity database: `backup` and `restore`. They read the same `WOHP_SERVER_CORE_DB`, `WOHP_SERVER_CORE_KEY` and `WOHP_SERVER_DB` as the server, never create a lookup key and print only file names and counts.

```sh
wohp-server backup /var/backups/wohp         # safe while the server runs
wohp-server restore /var/backups/wohp/wohp-identity-<time>.sqlite3
```

`backup` opens the database read-only and writes a consistent snapshot (SQLite `VACUUM INTO`, which includes the write-ahead log) as `wohp-identity-<unix time>.sqlite3`, mode `0600`, into an existing `0700` directory. It never overwrites a snapshot, checks the copy (`integrity_check`, foreign keys, schema version) and refuses a key that does not belong to the database. The snapshot keeps every subject, lookup reference, client subject, epoch and revocation, but **not the lookup key**: keep a separate, protected copy of the key (it never changes). The server database (verifications and one-time codes, valid for minutes) is not backed up.

`restore` runs with the server stopped and refuses to replace anything: move the old core database, the server database and their `-wal`/`-shm` files
aside first. A snapshot with a `-wal` or `-journal` file next to it is a live or interrupted database and is refused. The command copies the snapshot next to the target, checks it against the key, then, before giving it its name:

* deletes every challenge, so no verification started before the snapshot   can be completed or replayed 
* sets every authentication epoch to the restore time (Unix seconds) and records an `AUTHENTICATORS_RESET` event per person. Relying parties drop credentials and sessions from before the restore and people verify with the wallet again.

### Restore and authentication epochs

An epoch goes up by one at each recovery, revocation or authenticator reset.
Relying parties keep the highest epoch they have seen for a person and refuse a lower one, which would revive sessions they already ended.

**Why the restore time.** A snapshot is older than the lost database, so its epochs can be lower than those relying parties already hold. Example: a
person is revoked after the snapshot and client A stores epoch 5, the snapshot has 3. Restoring 3, or `3 + 1`, is refused by client A. Nobody knows how far the lost counters went, so no fixed increment is safe.
`restore` sets every epoch to the restore time in Unix seconds instead: a person would need more advances than seconds elapsed since the previous restore (or since 1970) to exceed it. Every session from before the restore ends.

**After a restore.** Epochs continue from that value (`T + 1`, `T + 2` ...), the next restore moves them to its own time. They are signed 64-bit integers, only compared and never shown to people.

**Refused restore.** A snapshot whose highest epoch is at or above the current time means the clock is behind a previous restore. Fix the clock
and restore again.

**What is lost.** Everything after the snapshot: later enrollments get a new subject at the next verification, later revocations must be applied again, and sessions end for everyone. Back up often enough for that window to be
acceptable.


### Minimum age per client

There is no deployment-wide age floor. Each registered client carries its own minimum age: `13`, `14`, `16`, `18`, or `none` to accept everyone and only deduplicate. A school vote can therefore accept a child without an EUDI credential, while a social network can require 14 or 18.

For the single client in the environment, set `WOHP_CLIENT_MIN_AGE`, with `WOHP_CLIENTS_FILE`, every client entry needs `minimum_age` (a number or `null`). The floor is checked when a challenge is issued and again when the person is stored: below it the verification is refused and nothing is
written. The floor is fixed into the existing challenge, not read again at completion.

If the configured minimum age of an existing client changes, the server applies it at startup and records `MINIMUM_AGE_CHANGED` in `client_events`.
The previous floor is audited with it. People whose evidence no longer meets the new floor become `RevalidationRequired` for that client, their profile, pairwise subjects and epochs are untouched.

## Try the development mock

Requires Rust **1.98.1** (pinned in `rust-toolchain.toml`), a C compiler for reviewed native dependencies, and write access to a private local directory. From the repository root:

```sh
cargo run --locked -p wohp --features mock --bin wohp-mock -- keygen ./lookup.key
cargo run --locked -p wohp --features mock --bin wohp-mock -- ./identity.sqlite3 ./lookup.key demo
```

The demo creates fixture Alice, resolves a repeated enrollment to the same subject, revokes it and recovers it with a higher authentication epoch.
It also registers a school vote with no minimum age and a social network with a minimum age of 13, showing the same child accepted by the first and refused by the second. It issues no signed ID token and grants no application
session.

For individual fixture operations:

```sh
cargo run --locked -p wohp --features mock --bin wohp-mock -- ./identity.sqlite3 ./lookup.key \
  client school-vote school.example none
cargo run --locked -p wohp --features mock --bin wohp-mock -- ./identity.sqlite3 ./lookup.key \
  client social social.example 13
cargo run --locked -p wohp --features mock --bin wohp-mock -- ./identity.sqlite3 ./lookup.key \
  enroll fixture-bob 13 social
cargo run --locked -p wohp --features mock --bin wohp-mock -- ./identity.sqlite3 ./lookup.key \
  status SUBJECT
cargo run --locked -p wohp --features mock --bin wohp-mock -- ./identity.sqlite3 ./lookup.key \
  revoke SUBJECT
cargo run --locked -p wohp --features mock --bin wohp-mock -- ./identity.sqlite3 ./lookup.key \
  recover SUBJECT fixture-bob adult
```

Copy `SUBJECT` from the enrollment output. `fixture-bob` is a local string, not civil identity evidence. An `enroll` command on the same fixture returns `ExistingRequiresAuthentication` that return value is not a login.

`enroll` takes an optional fixture age (`13`, `14`, `16`, `18`, `adult`, `underage` or `unknown`) and an optional registered client. With a client, the enrollment is refused below that client's minimum age and nothing is stored.
`client` registers a client id and scope with `13`, `14`, `16`, `18` or `none`, changing the minimum age of an existing client is audited.
`client-status CLIENT_ID CLIENT_SUBJECT` resolves the threshold for that client. These are development fixtures, not age verification.

There is no deployment-wide floor and no `set-floor` command: each client carries its own minimum age, and the database is created at the current schema only. A database created by an earlier schema is refused rather than migrated, delete it, its `-wal`/`-shm` files and start again. File names ending in `.key`/`.sqlite3` and `target/` are excluded by `.gitignore`, but
protect and back up local data explicitly. Do not expose this privileged simulator as a network service.

## Try a wallet presentation QR (local spike)

An optional local QR page can drive an independently deployed EUDI Verifier Endpoint (Kotlin), using the same OpenID4VP profile as the FormEU test PID. It needs RP credentials registered with that verifier and a verifier URL reachable from the phone, `.env.example` lists the settings.
It requires `--features server` (binary `wohp-server`) and `WOHP_SERVER_ENV=development` to start. It is the WOHP Identity server:
registered clients start verifications and redeem a one-time code server-to-server for a pairwise subject, an epoch and an age threshold. The core issues the challenge and nonce, matches and deduplicates the person. That evidence is still `DevelopmentOnly`: no `unique_human`, no production human, and the verifier sandbox is a shared third party.
Several relying parties can be registered from configuration. WOHP Identity knows nothing about a relying party's sessions, OIDC provider or login
challenges.

## Container image

`Dockerfile` builds the `wohp-server` image. Deployments that combine it with relying parties live in those parties' repositories, none of them turns the mock, a passkey or the QR presentation into verified identity evidence.

## What remains for the v1.0.1 integration

* A real EUDI PID verifier/matching adapter with issuer trust, profile   validation, holder binding, status checks and approved production access.
The adapter alone can claim production evidence when those requirements   are actually met, the mock cannot.


## Verification

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo tree --locked
cargo tree --duplicates --locked
cargo audit --deny warnings
```

The integration tests cover concurrent duplicate enrollment and redemption, restart persistence, ambiguous/unavailable/expired evidence, cross-challenge and replay rejection, subject/epoch continuity, revocation races, per-client
minimum ages, private lookup storage, permissions and mock/production isolation. Test
fixtures are deliberately not certified identity evidence.

## Licence

Licensed under the European Union Public Licence v. 1.2 (`EUPL-1.2`), see [`LICENSE`](LICENSE).

## Demo applications using WOHP Identity

* https://poll.flare.it a voting system  (tested with the Hopae EU reference Wallet)
* https://elite.flare.it Knowledge Agora, reference implementation of a social network built on top of WOHP Identity and WOHP Bootstrap, a Rust module not yet published that handles WebAuthn access (mobile and hardware keys), OIDC, de-duplicated sessions and more. The Agora features a Usenet-inspired taxonomy with namespaces, reputation, multi-level moderation, closed rooms, guest accesses and i18n.

TODO: publish the Poll source code and the WOHP Bootstrap module, and expand this documentation.