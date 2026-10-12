"""Runnable synthetic backup/recovery walkthrough; never reads user files.

All archives and random demo keys live in an automatically removed temporary
directory. Only a non-secret verification report remains. Requires a built JS
bridge and tools/requirements-dev.txt in the current Python environment.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'examples/secretstream-file/cli.cjs'
REFERENCE = ROOT / 'examples/secretstream-file/reference.py'


def command(args, succeeds=True):
    result = subprocess.run(list(map(str, args)), text=True, capture_output=True, timeout=120)
    if succeeds and result.returncode != 0:
        raise RuntimeError(result.stderr[-2000:])
    if not succeeds and result.returncode == 0:
        raise RuntimeError('Unsafe recovery unexpectedly succeeded')
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def demonstrate(report_path):
    report_path = Path(report_path).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    # Refuse to replace an earlier report; synthetic files are always isolated.
    with report_path.open('x', encoding='utf-8') as report_file:
        with tempfile.TemporaryDirectory(prefix='mbss-backup-') as directory:
            root = Path(directory)
            key = root / 'demo.key'
            fd = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as key_file:
                key_file.write(os.urandom(32))
            source = root / 'backup.jsonl'
            with source.open('w', encoding='utf-8', newline='\n') as data:
                for index in range(10000):
                    data.write(json.dumps(dict(id=index, value='synthetic backup record')) + '\n')
            moon_archive, python_archive = root / 'moon.mbss', root / 'python.mbss'
            node = ['node', CLI]
            python = [sys.executable, REFERENCE]
            command([*node, 'seal', source, moon_archive, key])
            command([*python, 'seal', source, python_archive, key])
            expected = digest(source)
            recoveries = []
            for implementation, executable, archive in [('libsodium', python, moon_archive),
                                                         ('MoonBit', node, python_archive)]:
                restored = root / (implementation + '.jsonl')
                command([*executable, 'open', archive, restored, key])
                if digest(restored) != expected:
                    raise RuntimeError('Recovered backup hash mismatch')
                records = [json.loads(line) for line in restored.read_text(encoding='utf-8').splitlines()]
                if len(records) != 10000 or any(record != dict(id=i, value='synthetic backup record')
                                               for i, record in enumerate(records)):
                    raise RuntimeError('Recovered backup content mismatch')
                recoveries.append(dict(reader=implementation, hashMatches=True, records=10000))
            # Remove the complete FINAL record: a valid prefix must not publish.
            truncated = root / 'incomplete.mbss'
            truncated.write_bytes(moon_archive.read_bytes()[:-21])
            for implementation, executable in [('MoonBit', node), ('libsodium', python)]:
                rejected = root / (implementation + '-incomplete.jsonl')
                command([*executable, 'open', truncated, rejected, key], succeeds=False)
                if rejected.exists() or list(root.glob(rejected.name + '.part-*')):
                    raise RuntimeError('Incomplete recovery published or left temporary plaintext')
                existing = root / (implementation + '-existing.jsonl')
                existing.write_bytes(b'preserve-existing-backup')
                command([*executable, 'open', moon_archive, existing, key], succeeds=False)
                if existing.read_bytes() != b'preserve-existing-backup':
                    raise RuntimeError('Existing backup overwritten')
            report = dict(syntheticOnly=True, sourceBytes=source.stat().st_size, sourceSha256=expected,
                          recoveries=recoveries, truncatedBackupRejectedByBoth=True,
                          noPublishedOrTemporaryPlaintextOnFailure=True,
                          existingBackupPreservedByBoth=True,
                          envelope='MBSS0001 project-specific framing; libsodium-compatible frames',
                          notes='Demonstration only; no password derivation, key backup/recovery or secret erasure guarantee.')
        report['temporaryDemoDirectoryRemoved'] = not root.exists()
        json.dump(report, report_file, indent=2)
        report_file.write('\n')
    print('PASS: cross-language recovery, incomplete backup rejection and output preservation')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', help='New JSON report path; existing files are not overwritten')
    demonstrate(parser.parse_args().report)
