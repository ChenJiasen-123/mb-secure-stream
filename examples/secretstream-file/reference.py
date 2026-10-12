"""Independent libsodium file adapter for the MBSS0001 example envelope."""
import json
import os
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

def exact(source, length):
    data = source.read(length)
    if len(data) != length:
        raise ValueError('Truncated file')
    return data

def run(mode, source_path, dest_path, key_path, chunk=65536):
    key = Path(key_path).read_bytes()
    if len(key) != 32 or not 1 <= chunk <= MAX or mode not in ('seal', 'open'):
        raise ValueError('Invalid arguments')
    temporary = Path(str(dest_path) + '.part-' + os.urandom(12).hex())
    started = time.perf_counter()
    try:
        with open(source_path, 'rb') as source, temporary.open('xb') as dest:
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
        return dict(mode=mode, elapsedSeconds=time.perf_counter()-started)
    finally:
        temporary.unlink(missing_ok=True)

if __name__ == '__main__':
    print(json.dumps(run(*sys.argv[1:5], chunk=int(sys.argv[5]) if len(sys.argv)>5 else 65536)))
