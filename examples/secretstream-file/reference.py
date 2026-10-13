"""Independent libsodium file adapter for the MBSS0001 example envelope."""
import json
import os
import stat
import sys
import time
from pathlib import Path
from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_state as State,
    crypto_secretstream_xchacha20poly1305_init_push as init_push,
    crypto_secretstream_xchacha20poly1305_init_pull as init_pull,
    crypto_secretstream_xchacha20poly1305_push as push,
    crypto_secretstream_xchacha20poly1305_pull as pull,
)

MAGIC = b'MBSS0001'
MAX = 1024 * 1024

def open_regular(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Input or key must be a regular file')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def read_key(path):
    with open_regular(path) as source:
        if os.fstat(source.fileno()).st_size != 32:
            raise ValueError('Key file must contain exactly 32 binary bytes')
        key = source.read(33)
    if len(key) != 32:
        raise ValueError('Key file must contain exactly 32 binary bytes')
    return key


def exact(source, length):
    data = source.read(length)
    if len(data) != length:
        raise ValueError('Truncated file')
    return data

def run(mode, source_path, dest_path, key_path, chunk=65536):
    key = read_key(key_path)
    if len(key) != 32 or not 1 <= chunk <= MAX or mode not in ('seal', 'open'):
        raise ValueError('Invalid arguments')
    temporary = Path(str(dest_path) + '.part-' + os.urandom(12).hex())
    started = time.perf_counter()
    temporary_owned = False
    try:
        with open_regular(source_path) as source:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            temporary_owned = True
            with os.fdopen(fd, 'wb') as dest:
                state = State()
                if mode == 'seal':
                    header = init_push(state, key)
                    dest.write(MAGIC + header)
                    while data := source.read(chunk):
                        frame = push(state, data, b'', 0)
                        dest.write(len(frame).to_bytes(4, 'little') + frame)
                    frame = push(state, b'', b'', 3)
                    dest.write(len(frame).to_bytes(4, 'little') + frame)
                else:
                    if exact(source, 8) != MAGIC:
                        raise ValueError('Invalid file header')
                    init_pull(state, exact(source, 24), key)
                    final = False
                    while prefix := source.read(4):
                        if final or len(prefix) != 4:
                            raise ValueError('Trailing or truncated frame')
                        size = int.from_bytes(prefix, 'little')
                        if not 17 <= size <= MAX + 17:
                            raise ValueError('Invalid frame size')
                        data, tag = pull(state, exact(source, size), b'')
                        dest.write(data)
                        final = tag == 3
                    if not final:
                        raise ValueError('Missing FINAL frame')
                dest.flush()
                os.fsync(dest.fileno())
        os.link(temporary, dest_path)
    except BaseException as error:
        if temporary_owned:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as cleanup:
                error.add_note(f'Retained temporary file {temporary}: {cleanup}')
        raise
    warnings = []
    try:
        temporary.unlink()
    except OSError as cleanup:
        warnings.append(f'Output committed; remove retained temporary file {temporary}: {cleanup}')
    return dict(mode=mode, outputCommitted=True, cleanupWarnings=warnings,
                elapsedSeconds=time.perf_counter()-started)

if __name__ == '__main__':
    print(json.dumps(run(*sys.argv[1:5], chunk=int(sys.argv[5]) if len(sys.argv)>5 else 65536)))
