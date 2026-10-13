# Cross-implementation streamed file example

Experimental example, not a security-audited file encryption product.
MoonBit implements all cryptography; the Node adapter only performs bounded
file I/O and publishes completed output. Python/PyNaCl provides an independent
libsodium reference for integration testing.

## Build and run

Requires MoonBit 0.10.15 (tested), Node 24 (tested), and a filesystem supporting
same-directory hard links. The optional reference tests require Python 3.12 and
`python -m pip install -r tools/requirements-dev.txt` in an isolated environment.

From the repository root:

```sh
node examples/secretstream-file/cli.cjs --help
moon build --target js examples/secretstream-file/bridge
node examples/secretstream-file/cli.cjs seal INPUT ENCRYPTED KEYFILE
node examples/secretstream-file/cli.cjs open ENCRYPTED RESTORED KEYFILE
python tools/verify_secretstream_files.py RESULTS.json 1 16 64
python tools/verify_secretstream_files.py RESULTS-4k.json 1 16 --chunk-bytes 4096
python tools/verify_secretstream_files.py RESULTS-1m.json 1 16 --chunk-bytes 1048576
```

KEYFILE must contain exactly 32 binary bytes. For a **throwaway local demo**,
generate a key with the OS CSPRNG, for example:

```sh
node -e "require('node:fs').writeFileSync('demo.key',require('node:crypto').randomBytes(32),{flag:'wx',mode:0o600})"
```

Never use the checked-in test-vector key for private data. This example does
not implement password-based key derivation, key storage, backup or recovery.
Avoid sharing key files and ciphertext together. No keys are embedded in the
container or printed in the metrics. OS permissions and JavaScript GC do not
provide guaranteed secret-memory erasure.

Each encryption calls the MoonBit JavaScript sender factory, which obtains a
fresh 24-byte header through the existing CSPRNG provider. Entropy failure is
an error. The public sender has no fixed-header constructor. Reader and writer
types are separate and internal state is not exposed through the MoonBit API.

## Example envelope

This project-specific envelope is **not** a libsodium-defined file format.
Its individual ciphertext records use the compatible libsodium secretstream
wire representation. Both example adapters implement this same framing:

1. Eight ASCII bytes `MBSS0001`.
2. The 24-byte secretstream header.
3. Repeated four-byte unsigned little-endian record length and ciphertext.
4. A final empty message with the authenticated FINAL tag.

Default data chunks are 64 KiB, configurable up to 1 MiB. Ciphertext overhead
is 17 bytes per record, plus the four-byte length. Reader allocation is capped
before reading a record. No whole-file array is retained by the Node adapter.
The format intentionally does not store a filename or restore filesystem
metadata. Do not confuse per-frame authenticated output with whole-file
completion: the final marker and EOF must both be checked.

Decryption writes only to a newly created temporary file until every frame,
FINAL and EOF have been verified. An error removes this temporary file.
Successful output is published via an exclusive hard link; an existing
destination is never overwritten. This example fails on filesystems that do
not support this operation instead of silently weakening that behavior.

## Evidence and limits

The verification harness checks MoonBit encryption → libsodium decryption and
libsodium encryption → MoonBit decryption, comparing SHA-256 of all outputs.
It also checks eight classes of damaged/truncated containers, absence of
published/temporary plaintext on failure, and preservation of an existing
destination. Inputs are synthetic, with no user files or credentials involved.

Metrics use a fresh Node process per operation and report total process peak
RSS, including V8, JIT and GC; this is not just algorithm working memory.
When setting `NODE_OPTIONS=--max-old-space-size=64`, that option is recorded in
the results and applies to V8 old-space, not a 64 MiB total RSS limit. Report
unrestricted measurements separately. No measured results imply an audit,
constant-time machine code, production readiness, or superiority to native C.

For repeated measurements with separate raw JSON files and descriptive
min/median/max summaries:

```sh
python tools/measure_secretstream_repeated.py repeated.json --repeats 3 --sizes 1 16 --chunks 65536 1048576
```

Chunk order alternates between rounds. Each round also reruns both directions
of interoperability and the negative cases; this is not an isolated primitive
benchmark. The summary records the runtime, platform, `NODE_OPTIONS` and source
hashes. Run a different output prefix when changing heap options; keep the raw
files with the summary. Three samples do not establish a confidence interval.

CLI metrics report the configured `chunkBytes` only for encryption. Decryption
uses record lengths from its input and reports `chunkBytes: null`; both modes
report `maxPlaintextFrameBytes` actually processed. Earlier versions reported
the unused default CLI chunk value during decryption, so use the harness's
top-level `chunkBytes` to interpret those historical measurement files.

## 发布提交点与清理警告

同目录硬链接创建最终输出成功即为提交点。成功报告含 `outputCommitted: true` 和 `cleanupWarnings`。之后临时链接删除失败时，命令仍成功返回，但警告给出需要清理的临时路径；最终输出已存在且可使用，不应盲目重试加解密。输出始终不覆盖已有文件。

提交前失败仍抛出原始错误；关闭或删除临时文件也失败时附带清理警告，不覆盖原始错误。文件 fsync 和原子发布不构成跨文件系统或断电后的目录持久性保证。
