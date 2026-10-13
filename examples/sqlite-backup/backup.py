"""Consistent SQLite snapshots encrypted by the compiled MoonBit file adapter."""
import argparse
from contextlib import closing
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'examples/secretstream-file/cli.cjs'


def readonly(path):
    connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2)
    connection.execute('PRAGMA trusted_schema=OFF')
    connection.execute('PRAGMA query_only=ON')
    return connection


def validate_database(path, timeout):
    with path.open('rb') as source:
        if source.read(16) != b'SQLite format 3\x00':
            raise ValueError('Not an initialized SQLite database')
    with closing(readonly(path)) as database:
        deadline = time.monotonic() + timeout
        database.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        if database.execute('PRAGMA integrity_check').fetchone() != ('ok',):
            raise ValueError('SQLite integrity check failed')


def snapshot_database(source, snapshot, timeout):
    if not source.is_file():
        raise ValueError('Database must be an existing regular file')
    fd = os.open(snapshot, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    deadline = time.monotonic() + timeout
    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise TimeoutError('SQLite snapshot deadline exceeded')
    with closing(readonly(source)) as database, closing(sqlite3.connect(snapshot)) as target:
        database.backup(target, pages=128, progress=progress, sleep=0.05)
        # Make the image self-contained before encrypting just this file.
        if target.execute('PRAGMA journal_mode=DELETE').fetchone() != ('delete',):
            raise ValueError('Could not finalize standalone SQLite snapshot')
    validate_database(snapshot, timeout)


def file_adapter(mode, source, output, key, timeout):
    result = subprocess.run(['node', str(CLI), mode, str(source), str(output), str(key)],
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'MoonBit file adapter failed')
    report = json.loads(result.stdout)
    if report.get('outputCommitted') is not True:
        raise RuntimeError('MoonBit adapter did not confirm publication')
    return report


def check_destination(output, restore):
    paths = [output]
    if restore:
        paths += [Path(str(output) + suffix) for suffix in ('-wal', '-shm', '-journal')]
    if any(os.path.lexists(path) for path in paths):
        raise FileExistsError('Destination or SQLite sidecar already exists')


def run(mode, source, output, key, timeout=120):
    if mode not in ('backup', 'restore') or not math.isfinite(timeout) or not 0 < timeout <= 3600:
        raise ValueError('Invalid operation or timeout (0 < seconds <= 3600)')
    source = Path(source).resolve(strict=True)
    key = Path(key).resolve(strict=True)
    if not source.is_file() or not key.is_file() or key.stat().st_size != 32:
        raise ValueError('Input must be a regular file; key must be a 32-byte regular file')
    # Resolve the parent only: following an existing destination symlink would be unsafe.
    requested = Path(os.path.abspath(output))
    output = requested.parent.resolve(strict=True) / requested.name
    check_destination(output, mode == 'restore')
    stage = Path(tempfile.mkdtemp(prefix='.mbss-sqlite-', dir=output.parent))
    published = stage / ('backup.mbss' if mode == 'backup' else 'restored.sqlite')
    try:
        if mode == 'backup':
            snapshot = stage / 'snapshot.sqlite'
            snapshot_database(source, snapshot, timeout)
            adapter = file_adapter('seal', snapshot, published, key, timeout)
        else:
            adapter = file_adapter('open', source, published, key, timeout)
            validate_database(published, timeout)
        check_destination(output, mode == 'restore')
        # Commit point: publish a complete verified file without replacing any target.
        os.link(published, output)
    except BaseException as error:
        try:
            shutil.rmtree(stage)
        except OSError as cleanup:
            error.add_note(f'Retained private staging directory {stage}: {cleanup}')
        raise
    warnings = []
    try:
        shutil.rmtree(stage)
    except OSError as cleanup:
        warnings.append(f'Output committed; remove private staging directory {stage}: {cleanup}')
    return dict(operation=mode, outputCommitted=True, cleanupWarnings=warnings,
                sqliteVersion=sqlite3.sqlite_version, integrityChecked=True,
                cryptoImplementation='MoonBit secretstream via Node I/O adapter',
                frames=adapter['frames'], plaintextBytes=adapter['inputBytes'] if mode == 'backup' else adapter['outputBytes'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['backup', 'restore'])
    parser.add_argument('input')
    parser.add_argument('output', help='New output path in an existing trusted directory')
    parser.add_argument('key', help='Existing 32-byte binary key file')
    parser.add_argument('--timeout-seconds', type=float, default=120)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.operation, args.input, args.output, args.key, args.timeout_seconds)))
    except Exception as error:
        parser.exit(1, str(error) + '\n' + '\n'.join(getattr(error, '__notes__', [])) + '\n')
