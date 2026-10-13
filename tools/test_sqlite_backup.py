"""Exercise actual SQLite snapshots and MoonBit encrypted recovery on synthetic data."""
from contextlib import closing
import importlib.util
import argparse
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sqlite_backup_app', ROOT / 'examples/sqlite-backup/backup.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class SQLiteBackup(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='mbss-sqlite-test-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.db = self.root / 'database #snapshot.sqlite'
        self.key = self.root / 'demo.key'
        self.archive = self.root / 'backup.mbss'
        self.restored = self.root / 'restored.sqlite'
        self.key.write_bytes(os.urandom(32))
        self.writer = sqlite3.connect(self.db)
        self.addCleanup(self.writer.close)
        self.writer.execute('CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT)')
        self.writer.commit()

    def no_stage(self):
        self.assertFalse(list(self.root.glob('.mbss-sqlite-*')))

    def backup(self):
        result = app.run('backup', self.db, self.archive, self.key)
        self.assertTrue(result['outputCommitted'])
        self.assertTrue(result['integrityChecked'])
        return result

    def test_wal_commits_captured_and_pending_transaction_excluded(self):
        self.writer.execute('PRAGMA journal_mode=WAL')
        self.writer.executemany('INSERT INTO records VALUES (?,?)', [(1, 'first'), (2, 'second')])
        self.writer.commit()
        self.assertGreater(Path(str(self.db) + '-wal').stat().st_size, 0)
        self.writer.execute('INSERT INTO records VALUES (3, "uncommitted")')
        self.backup()
        result = app.run('restore', self.archive, self.restored, self.key)
        self.assertTrue(result['outputCommitted'])
        with closing(sqlite3.connect(self.restored)) as restored:
            self.assertEqual(restored.execute('SELECT * FROM records ORDER BY id').fetchall(), [(1, 'first'), (2, 'second')])
            self.assertEqual(restored.execute('PRAGMA integrity_check').fetchone(), ('ok',))
        # Independently decrypt the same archive with libsodium.
        reference = self.root / 'libsodium.sqlite'
        completed = subprocess.run([sys.executable, str(ROOT / 'examples/secretstream-file/reference.py'), 'open', str(self.archive), str(reference), str(self.key)], capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(reference.read_bytes(), self.restored.read_bytes())
        self.assertEqual(self.writer.execute('SELECT count(*) FROM records').fetchone(), (3,))
        self.no_stage()

    def test_initialized_empty_database_roundtrip(self):
        self.backup()
        app.run('restore', self.archive, self.restored, self.key)
        with closing(sqlite3.connect(self.restored)) as restored:
            self.assertEqual(restored.execute('SELECT count(*) FROM records').fetchone(), (0,))
        self.no_stage()

    def test_wrong_key_and_truncated_archive_do_not_publish(self):
        self.backup()
        other = self.root / 'wrong.key'
        other.write_bytes(os.urandom(32))
        with self.assertRaises(RuntimeError):
            app.run('restore', self.archive, self.restored, other)
        self.assertFalse(self.restored.exists())
        truncated = self.root / 'truncated.mbss'
        truncated.write_bytes(self.archive.read_bytes()[:-21])
        with self.assertRaises(RuntimeError):
            app.run('restore', truncated, self.restored, self.key)
        self.assertFalse(self.restored.exists())
        self.no_stage()

    def test_authenticated_non_database_is_rejected_after_decryption(self):
        bad = self.root / 'bad.sqlite'
        for data in [b'not a database', b'SQLite format 3\x00' + bytes(64)]:
            bad.write_bytes(data)
            archive = self.root / ('invalid-' + str(len(data)) + '.mbss')
            app.file_adapter('seal', bad, archive, self.key, 30)
            with self.assertRaises((ValueError, sqlite3.DatabaseError)):
                app.run('restore', archive, self.restored, self.key)
            self.assertFalse(self.restored.exists())
            self.no_stage()

    def test_existing_target_and_sqlite_sidecars_preserved(self):
        self.backup()
        for suffix in ['', '-wal', '-shm', '-journal']:
            existing = Path(str(self.restored) + suffix)
            existing.write_bytes(b'preserve')
            with self.assertRaises(FileExistsError):
                app.run('restore', self.archive, self.restored, self.key)
            self.assertEqual(existing.read_bytes(), b'preserve')
            existing.unlink()
        with self.assertRaises(FileExistsError):
            app.run('backup', self.db, self.archive, self.key)
        self.no_stage()

    def test_publish_race_cannot_replace_competing_file(self):
        link = os.link
        def compete(source, output):
            output.write_bytes(b'competitor')
            return link(source, output)
        with patch.object(app.os, 'link', compete):
            with self.assertRaises(FileExistsError):
                self.backup()
        self.assertEqual(self.archive.read_bytes(), b'competitor')
        self.no_stage()

    def test_cleanup_failure_after_commit_is_warning(self):
        with patch.object(app.shutil, 'rmtree', side_effect=PermissionError('injected cleanup failure')):
            result = self.backup()
        self.assertTrue(self.archive.exists())
        self.assertEqual(len(result['cleanupWarnings']), 1)
        app.run('restore', self.archive, self.restored, self.key)
        self.assertTrue(self.restored.exists())

    def test_cleanup_failure_preserves_original_error(self):
        with patch.object(app, 'file_adapter', side_effect=RuntimeError('injected encryption failure')):
            with patch.object(app.shutil, 'rmtree', side_effect=PermissionError('cleanup failure')):
                with self.assertRaisesRegex(RuntimeError, 'injected encryption failure') as failure:
                    self.backup()
        self.assertTrue(failure.exception.__notes__)
        self.assertFalse(self.archive.exists())

    def test_missing_invalid_database_and_invalid_timeouts_leave_no_output(self):
        bad = self.root / 'bad-source.sqlite'
        bad.write_bytes(b'invalid database')
        for source in [self.root / 'missing', bad]:
            with self.assertRaises((OSError, ValueError, sqlite3.DatabaseError)):
                app.run('backup', source, self.archive, self.key)
            self.assertFalse(self.archive.exists())
            self.no_stage()
        for timeout in [0, -1, float('nan'), float('inf'), 3601]:
            with self.assertRaises(ValueError):
                app.run('backup', self.db, self.archive, self.key, timeout)
        self.no_stage()

    def test_snapshot_deadline_aborts_without_publishing(self):
        with patch.object(app.time, 'monotonic', side_effect=[0, 2]):
            with self.assertRaises(TimeoutError):
                app.run('backup', self.db, self.archive, self.key, timeout=1)
        self.assertFalse(self.archive.exists())
        self.no_stage()

    @unittest.skipUnless(os.name == 'posix', 'POSIX modes and symlinks')
    def test_private_staging_and_dangling_destination_symlink(self):
        adapter = app.file_adapter
        def inspect(mode, source, output, key, timeout):
            self.assertEqual(stat.S_IMODE(source.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
            return adapter(mode, source, output, key, timeout)
        with patch.object(app, 'file_adapter', inspect):
            self.backup()
        app.run('restore', self.archive, self.restored, self.key)
        self.assertEqual(stat.S_IMODE(self.restored.stat().st_mode), 0o600)
        self.restored.unlink()
        self.restored.symlink_to(self.root / 'absent-target')
        with self.assertRaises(FileExistsError):
            app.run('restore', self.archive, self.restored, self.key)
        self.assertTrue(self.restored.is_symlink())
        self.assertFalse((self.root / 'absent-target').exists())
        self.no_stage()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    result = unittest.main(argv=[sys.argv[0]], exit=False).result
    if args.report:
        with args.report.open('x', encoding='utf-8') as report:
            json.dump(dict(testsRun=result.testsRun, failures=len(result.failures),
                           errors=len(result.errors), skipped=len(result.skipped),
                           successful=result.wasSuccessful(), python=sys.version.split()[0],
                           sqlite=sqlite3.sqlite_version,
                           node=subprocess.check_output(['node', '--version'], text=True).strip(),
                           syntheticOnly=True), report, indent=2)
            report.write('\n')
    sys.exit(0 if result.wasSuccessful() else 1)
