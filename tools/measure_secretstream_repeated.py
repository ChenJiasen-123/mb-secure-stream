"""Repeated synthetic file interoperability measurements, preserving every raw run.

Build the JS bridge first. Output is descriptive process RSS/timing evidence,
not an isolated crypto benchmark, statistical confidence interval or audit.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def measure(output, repeats, sizes, chunks):
    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    runs = []
    for iteration in range(repeats):
        # Alternate order to reduce a fixed ordering bias; no confidence claim.
        for chunk in (chunks if iteration % 2 == 0 else list(reversed(chunks))):
            raw_path = output.with_name(f'{output.stem}-chunk{chunk}-run{iteration + 1}.json')
            subprocess.run([sys.executable, str(ROOT / 'tools/verify_secretstream_files.py'),
                            str(raw_path), *map(str, sizes), '--chunk-bytes', str(chunk)],
                           check=True, timeout=600)
            raw = json.loads(raw_path.read_text(encoding='utf-8'))
            if (not all(case['crossImplementationHashesMatch'] for case in raw['cases'])
                    or len(raw['negativeCases']) != 8
                    or not all(case['bothReject'] and case['noPublishedOrPartialOutput'] for case in raw['negativeCases'])
                    or not raw['existingOutputPreserved']):
                raise RuntimeError('Incomplete interoperability evidence')
            runs.append(dict(iteration=iteration + 1, chunkBytes=chunk, rawFile=raw_path.name,
                             sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(), result=raw))
    summary = []
    for chunk in chunks:
        for size in sizes:
            for operation in ['moonSeal', 'moonOpen']:
                samples = [case[operation] for run in runs if run['chunkBytes'] == chunk
                           for case in run['result']['cases'] if case['sizeMiB'] == size]
                row = dict(chunkBytes=chunk, sizeMiB=size, operation=operation, samples=len(samples))
                for metric in ['elapsedSeconds', 'peakRssMiB']:
                    values = [sample[metric] for sample in samples]
                    row[metric] = dict(min=min(values), median=statistics.median(values), max=max(values))
                summary.append(row)
    sources = ['examples/secretstream-file/cli.cjs', 'tools/verify_secretstream_files.py',
               'tools/measure_secretstream_repeated.py',
               '_build/js/debug/build/examples/secretstream-file/bridge/bridge.js']
    report = dict(repeats=repeats, sizesMiB=sizes, chunksBytes=chunks,
                  nodeOptions=os.environ.get('NODE_OPTIONS', ''), platform=platform.platform(),
                  python=platform.python_version(),
                  node=subprocess.check_output(['node', '--version'], text=True).strip(),
                  sourceSha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sources},
                  summary=summary, rawRuns=[{k: v for k, v in run.items() if k != 'result'} for run in runs],
                  notes='Alternating chunk order; fresh Node process per operation; synthetic repeated-byte input; total process peak RSS including V8/JIT/GC. Min/median/max are descriptive only. Do not compare different NODE_OPTIONS as identical configurations.')
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f'PASS: {len(runs)} raw runs saved; summary written', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--sizes', type=int, nargs='+', default=[1, 16])
    parser.add_argument('--chunks', type=int, nargs='+', default=[65536, 1048576])
    args = parser.parse_args()
    if not 2 <= args.repeats <= 20 or any(size < 1 for size in args.sizes):
        parser.error('repeats must be 2..20 and sizes must be positive MiB')
    if (len(set(args.sizes)) != len(args.sizes) or len(set(args.chunks)) != len(args.chunks)
            or any(not 1 <= chunk <= 1048576 for chunk in args.chunks)):
        parser.error('sizes/chunks must be unique and chunks must be 1..1048576 bytes')
    measure(args.output, args.repeats, args.sizes, args.chunks)
