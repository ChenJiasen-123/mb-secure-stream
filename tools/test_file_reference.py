"""Filesystem failure regression tests for the independent reference adapter."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
REFERENCE = Path(__file__).resolve().parents[1] / 'examples/secretstream-file/reference.py'
spec = importlib.util.spec_from_file_location('file_reference', REFERENCE)
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


class ReferenceFiles(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='mbss-reference-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source, self.key, self.output = (self.root / name for name in ('input', 'key', 'output'))
        self.source.write_bytes(b'synthetic only')
        self.key.write_bytes(bytes(32))

    def test_collision_and_early_failure_preserve_unowned_path(self):
        temporary = Path(str(self.output) + '.part-' + '00' * 12)
        temporary.write_bytes(b'belongs to another operation')
        with patch.object(reference.os, 'urandom', return_value=bytes(12)):
            with self.assertRaises(FileExistsError):
                reference.run('seal', self.source, self.output, self.key)
            self.assertEqual(temporary.read_bytes(), b'belongs to another operation')
            with self.assertRaises(FileNotFoundError):
                reference.run('seal', self.root / 'missing', self.output, self.key)
            self.assertEqual(temporary.read_bytes(), b'belongs to another operation')
        self.assertFalse(self.output.exists())

    def test_large_key_rejected_without_read_bytes(self):
        with self.key.open('wb') as key:
            key.truncate(64 * 1024 * 1024)
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('unbounded key read')):
            with self.assertRaisesRegex(ValueError, 'exactly 32'):
                reference.run('seal', self.source, self.output, self.key)
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob('*.part-*')))

    def test_post_commit_cleanup_warning_preserves_valid_output(self):
        unlink = Path.unlink
        def fail_temporary(path, *args, **kwargs):
            if path.name.startswith('output.part-'):
                raise PermissionError('injected unlink failure')
            return unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', fail_temporary):
            result = reference.run('seal', self.source, self.output, self.key)
        self.assertTrue(result['outputCommitted'])
        self.assertEqual(len(result['cleanupWarnings']), 1)
        restored = self.root / 'restored'
        reference.run('open', self.output, restored, self.key)
        self.assertEqual(restored.read_bytes(), self.source.read_bytes())

    def test_cleanup_failure_preserves_primary_failure(self):
        with patch.object(reference.os, 'link', side_effect=OSError('publication failed')):
            with patch.object(Path, 'unlink', side_effect=PermissionError('cleanup failed')):
                with self.assertRaisesRegex(OSError, 'publication failed') as error:
                    reference.run('seal', self.source, self.output, self.key)
        self.assertTrue(error.exception.__notes__)
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX mode bits')
    def test_temporary_output_private_even_with_permissive_umask(self):
        link = os.link
        def check_mode(source, dest):
            self.assertEqual(stat.S_IMODE(os.stat(source).st_mode), 0o600)
            return link(source, dest)
        previous = os.umask(0)
        try:
            with patch.object(reference.os, 'link', check_mode):
                reference.run('seal', self.source, self.output, self.key)
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO')
    def test_fifo_input_and_key_fail_without_blocking(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        for source, key in [(fifo, self.key), (self.source, fifo)]:
            result = subprocess.run([sys.executable, str(REFERENCE), 'seal', str(source),
                                     str(self.output), str(key)], capture_output=True,
                                    text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('regular file', result.stderr)
            self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
