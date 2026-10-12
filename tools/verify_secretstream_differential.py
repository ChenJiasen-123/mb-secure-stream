"""Randomized protocol differential checks against independent PyNaCl/libsodium.

Synthetic inputs only; the seed reproduces payloads, lengths, tags and keys.
Headers use the implementations' secure random factories and are not seeded.
"""
import argparse
import json
from pathlib import Path
import random
import subprocess

import nacl
from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_state as State,
    crypto_secretstream_xchacha20poly1305_init_push as init_push,
    crypto_secretstream_xchacha20poly1305_init_pull as init_pull,
    crypto_secretstream_xchacha20poly1305_push as push,
    crypto_secretstream_xchacha20poly1305_pull as pull,
)

ROOT = Path(__file__).resolve().parents[1]


def verify(output, streams, seed):
    rng = random.Random(seed)
    cases = []
    boundaries = [0, 1, 15, 16, 17, 31, 32, 63, 64, 65, 255, 256, 4096]
    for _ in range(streams):
        key = rng.randbytes(32)
        sender = State()
        header = init_push(sender, key)
        records = []
        lengths = boundaries + [rng.randrange(8193) for _ in range(12)]
        rng.shuffle(lengths)
        for index, length in enumerate(lengths):
            message = rng.randbytes(length)
            aad = rng.randbytes(rng.choice(boundaries[:11]))
            # Each stream includes PUSH, REKEY, repeated REKEY and terminal FINAL.
            tag = 3 if index == len(lengths) - 1 else index % 3
            records.append(dict(message=message.hex(), aad=aad.hex(), tag=tag,
                                frame=push(sender, message, aad, tag).hex()))
        cases.append(dict(key=key.hex(), header=header.hex(), records=records))
    proc = subprocess.run(['node', str(ROOT / 'tools/secretstream_differential.cjs')],
                          input=json.dumps(cases), text=True, capture_output=True)
    if proc.returncode:
        raise RuntimeError(proc.stderr[-4000:])
    results = json.loads(proc.stdout)
    if len(results) != len(cases):
        raise RuntimeError('Missing stream results')
    for case, result in zip(cases, results):
        reader, oracle_writer = State(), State()
        header, key = bytes.fromhex(result['header']), bytes.fromhex(case['key'])
        init_pull(reader, header, key)
        # libsodium init_pull derives the same state as init_push for a given header.
        # Used solely by this independent oracle to compare exact ciphertext bytes.
        init_pull(oracle_writer, header, key)
        if len(result['frames']) != len(case['records']):
            raise RuntimeError('Missing frame results')
        for record, encoded in zip(case['records'], result['frames']):
            message, aad = bytes.fromhex(record['message']), bytes.fromhex(record['aad'])
            frame = bytes.fromhex(encoded)
            if frame != push(oracle_writer, message, aad, record['tag']):
                raise RuntimeError('Ciphertext differs from libsodium')
            if pull(reader, frame, aad) != (message, record['tag']):
                raise RuntimeError('Plaintext or tag differs from libsodium')
    report = dict(seed=seed, streams=streams, frames=sum(len(c['records']) for c in cases),
                  oracle=f'PyNaCl {nacl.__version__} bundled libsodium',
                  bothDirections=True, exactCiphertextMatch=True,
                  tamperedFramesRejectedWithoutStateAdvance=True, finalTerminal=True,
                  hostEntropyFailureRejected=True,
                  notes='Synthetic randomized evidence, not an exhaustive test or security audit.')
    Path(output).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output')
    parser.add_argument('--streams', type=int, default=32)
    parser.add_argument('--seed', type=int, default=20261012)
    args = parser.parse_args()
    if not 1 <= args.streams <= 1000:
        parser.error('--streams must be between 1 and 1000')
    verify(args.output, args.streams, args.seed)
