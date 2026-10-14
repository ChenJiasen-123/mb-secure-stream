# OpenSeek offline session archive

An experimental application adapter for `moonbitlang/openseek@0.6.2` session
JSONL files. The actual upstream parser reconstructs a Session before encryption
and after authenticated decryption. Cryptography runs in the existing MoonBit
secretstream bridge; Node handles files and publication.

This demonstrates compatibility with public upstream data and APIs. OpenSeek
has not adopted this adapter, and no private user sessions were used in testing.

## Build and use

Tested with MoonBit 0.10.15 and Node 24. The destination filesystem must support
hard links. Build from the repository root:

```sh
moon build --target js examples/secretstream-file/bridge
cd examples/openseek-archive/consumer
moon update
moon build reader --target js --deny-warn
cd ../../..
node examples/openseek-archive/archive.cjs --help
node examples/openseek-archive/archive.cjs pack SESSION.jsonl SESSION.mbss KEYFILE --offline
node examples/openseek-archive/archive.cjs restore SESSION.mbss RECOVERED.jsonl KEYFILE --expect-id SESSION_ID
```

KEYFILE contains exactly 32 binary bytes. See the [file CLI instructions](../secretstream-file/README.md)
for key generation and storage limitations. The isolated consumer pins OpenSeek;
its substantial transitive dependency tree does not become a root library dependency.

## Contract and limits

- Stop the source session writer before using `--offline`. This flag acknowledges
  that condition; it does not acquire the native SessionStore lock. Snapshot
  metadata checks reject observed changes but cannot guarantee a live consistent copy.
- Only complete UTF-8 version-1 session files with contiguous event sequences
  starting at 1 are accepted. Unlike upstream recovery reads, partial tails and
  malformed events are rejected. Plaintext is capped at 32 MiB and parsed in memory.
- Restore authenticates the complete stream and validates the upstream session
  before publishing a new file. Existing destinations are never overwritten.
  `--expect-id` optionally verifies the archived session identity.
- `archive.cjs restore` produces a standalone JSONL file. `lifecycle.cjs restore`
  installs it into a new SessionStore root for subsequent CLI use. Neither changes
  an existing live store or bundles externally referenced images, files or job logs.
- Private staging files are removed on completion or failure. A cleanup failure
  reports their location; after publication it is a warning with `outputCommitted:true`.
  Use a trusted destination directory. Filesystem permissions are platform dependent.
- This is experimental cryptographic software without a security audit.

## Verification

After installing the repository's Python development requirements:

```sh
node tools/verify_openseek_archive.cjs RESULTS.json
```

Set `MBSS_PYTHON` to an isolated Python interpreter if needed. Verification uses
upstream constructors, the pinned public fixture, multi-frame Unicode data,
independent libsodium decryption, invalid logs, wrong keys, tampering, truncation,
destination preservation and staging cleanup. POSIX permissions and dangling
symlinks are checked only on POSIX. Filesystem SessionStore loading is outside
this verifier; the lifecycle verifier below exercises the real store.

## Real CLI lifecycle

The lifecycle wrapper runs the published OpenSeek 0.6.2 CLI via `moonx`, waits
for successful process exit, then automatically archives its completed session.
Use a dedicated session root and do not let other processes resume the same
session while it is being archived. Source plaintext remains on disk; this is
encrypted backup, not encryption of the active store. Model provider credentials
are configured normally for OpenSeek and are not managed by this adapter.

```sh
node examples/openseek-archive/lifecycle.cjs run ./session-store demo ./first.mbss KEYFILE -- --dir ./workspace "Explain this project"
node examples/openseek-archive/lifecycle.cjs restore ./recovered-store demo ./first.mbss KEYFILE
node examples/openseek-archive/lifecycle.cjs run ./recovered-store demo ./second.mbss KEYFILE -- --dir ./workspace "Continue the previous task"
```

The restore root must not exist, its parent must exist, and the archive output
must be new. IDs are restricted to portable letters, digits, underscores and
hyphens (maximum 128 characters). Only text-mode `run` arguments are supported.
An unsuccessful OpenSeek run produces no automatic archive. If archiving fails
after a successful run, its original session remains available for manual backup.

Reproduce without any model account or paid API call:

```sh
node tools/verify_openseek_lifecycle.cjs NEW_RESULTS.json
```

This invokes the documented `lifecycle.cjs` command entry points and the real
published OpenSeek CLI and filesystem SessionStore against a local deterministic
SSE provider. It automatically archives a completed turn, removes
only its own temporary source store, restores into a new root, calls upstream
`sessions show`, and resumes a second turn. Assertions inspect the actual model
request for restored history, check original event bytes remain unchanged, and
decrypt the automatically archived second turn to confirm its exact contents.
It proves storage and continuation integration, not real-model answer quality.

## Attribution

`fixtures/session-v1.jsonl` is copied unchanged from OpenSeek under Apache-2.0.
The exact commit, path and SHA-256 are recorded in [source.json](fixtures/source.json).
Source: https://github.com/moonbitlang/openseek/blob/17a35d963acc43ab2fc4a7de0a7cae3364a89019/agent_session/store/testdata/session-v1.jsonl
