"""Cross-implementation file integration and process peak-RSS measurements.

Requires Node, a built MoonBit JS bridge, and tools/requirements-dev.txt.
All test data and key material are synthetic. Output sizes are MiB.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / 'examples/secretstream-file/cli.cjs'
REFERENCE = REPO / 'examples/secretstream-file/reference.py'
CHUNK = 65536

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        while data := source.read(1024 * 1024):
            h.update(data)
    return h.hexdigest()

def command(args, ok=True):
    proc = subprocess.run([str(x) for x in args], capture_output=True, text=True)
    if ok and proc.returncode:
        raise RuntimeError(proc.stderr[-2000:])
    if not ok:
        assert proc.returncode != 0, 'Invalid input was accepted'
        return proc.stderr.strip()
    return json.loads(proc.stdout)

def main(output, sizes, chunk_bytes=65536):
    global CHUNK
    CHUNK = chunk_bytes
    results = dict(chunkBytes=CHUNK, sizesMiB=sizes, nodeOptions=os.environ.get('NODE_OPTIONS', ''), cases=[], negativeCases=[])
    with tempfile.TemporaryDirectory(prefix='secretstream-', dir=Path(output).parent) as tmp:
        root = Path(tmp)
        key = root/'test.key'
        key.write_bytes(bytes(range(32)))
        block = bytes(range(256)) * 4096
        for size in sizes:
            source = root/f'source-{size}.bin'
            with source.open('wb') as dest:
                for _ in range(size):
                    dest.write(block)
            encrypted = root/f'moon-{size}.mbss'
            pyout = root/f'python-{size}.out'
            reference = root/f'ref-{size}.mbss'
            moonout = root/f'moon-{size}.out'
            moon_seal = command(['node', CLI, 'seal', source, encrypted, key, CHUNK])
            command([sys.executable, REFERENCE, 'open', encrypted, pyout, key])
            command([sys.executable, REFERENCE, 'seal', source, reference, key, CHUNK])
            moon_open = command(['node', CLI, 'open', reference, moonout, key])
            expected = digest(source)
            assert expected == digest(pyout) == digest(moonout), 'File hash mismatch'
            results['cases'].append(dict(sizeMiB=size, sha256=expected,
                moonSeal=moon_seal, moonOpen=moon_open, crossImplementationHashesMatch=True))
            print(f'{size} MiB: both directions match; RSS seal/open '
                  f'{moon_seal["peakRssMiB"]:.1f}/{moon_open["peakRssMiB"]:.1f} MiB', flush=True)
            if size == sizes[0]:
                original = encrypted.read_bytes()
                cases = {}
                changed = bytearray(original)
                changed[40] ^= 1
                cases['tampered'] = bytes(changed)
                cases['missing-final'] = original[:-21]
                cases['truncated-prefix'] = original[:-1]
                cases['trailing-after-final'] = original + (17).to_bytes(4, 'little') + bytes(17)
                cases['oversized-prefix'] = original[:32] + (1048594).to_bytes(4, 'little')
                cases['invalid-header'] = b'WRONG000' + original[8:]
                cases['empty-stream'] = original[:32]
                cases['short-prefix'] = original[:32] + b'\x01'
                for name, data in cases.items():
                    bad = root/(name+'.mbss')
                    bad.write_bytes(data)
                    for impl, executable in [('moonbit', ['node', CLI]), ('libsodium', [sys.executable, REFERENCE])]:
                        rejected = root/f'{name}-{impl}.out'
                        command([*executable, 'open', bad, rejected, key], ok=False)
                        assert not rejected.exists(), 'Failed operation published plaintext'
                        assert not list(root.glob(rejected.name+'.part-*')), 'Failed operation left partial file'
                    results['negativeCases'].append(dict(name=name, bothReject=True, noPublishedOrPartialOutput=True))
                # Explicitly verify that existing destinations are preserved.
                preserved = root/'existing.out'
                preserved.write_bytes(b'keep-this')
                command(['node', CLI, 'open', encrypted, preserved, key], ok=False)
                assert preserved.read_bytes() == b'keep-this'
                results['existingOutputPreserved'] = True
            # Remove only known synthetic files so measurements do not accumulate disk use.
            for file in [source, encrypted, pyout, reference, moonout]:
                file.unlink()
    results['measurementNotes'] = 'Fresh Node process per operation; process.resourceUsage().maxRSS, including runtime/JIT/GC. Synthetic repeated-byte files, not a production throughput claim.'
    Path(output).write_text(json.dumps(results, indent=2)+'\n', encoding='utf-8')
    print(f'PASS: {len(sizes)} sizes, {len(results["negativeCases"])} negative cases x 2 implementations', flush=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output')
    parser.add_argument('sizes', type=int, nargs='*', default=[1, 16, 64])
    parser.add_argument('--chunk-bytes', type=int, default=65536)
    args = parser.parse_args()
    if not 1 <= args.chunk_bytes <= 1048576:
        parser.error('--chunk-bytes must be between 1 and 1048576')
    if any(size < 1 for size in args.sizes):
        parser.error('sizes must be positive MiB values')
    main(args.output, args.sizes, args.chunk_bytes)
