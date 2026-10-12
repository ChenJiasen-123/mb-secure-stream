"""Build and run a fresh isolated consumer of Mooncakes 0.2.0, not local sources."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def verify(output):
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError('Choose a new report path')
    phases = []
    with tempfile.TemporaryDirectory(prefix='mbss-consumer-') as directory:
        consumer = Path(directory) / 'consumer'
        shutil.copytree(ROOT / 'examples/published-consumer', consumer,
                        ignore=shutil.ignore_patterns('_build', '.mooncakes', 'target', '*.lock'))
        for args in [['moon', 'update'], ['moon', 'check', 'cmd/main', '--target', 'js', '--deny-warn'],
                     ['moon', 'run', 'cmd/main', '--target', 'js']]:
            started = time.monotonic()
            result = subprocess.run(args, cwd=consumer, text=True, capture_output=True, timeout=600)
            if result.returncode:
                raise RuntimeError(result.stderr[-3000:])
            if args[1] == 'run' and 'PASS: published secretstream package consumer' not in result.stdout:
                raise RuntimeError('Missing public consumer success marker')
            phases.append(dict(command=' '.join(args), seconds=time.monotonic() - started, passed=True))
        installed = consumer / '.mooncakes/ChenJiasen-123/mb-secure-stream/moon.mod'
        metadata = installed.read_text(encoding='utf-8')
        if not re.search(r'version\s*=\s*"0\.2\.0"', metadata):
            raise RuntimeError('Unexpected installed version')
    report = dict(module='ChenJiasen-123/mb-secure-stream', version='0.2.0', target='js',
                  freshConsumerDirectory=True, localSourceDependency=False,
                  installedVersionVerified=True, publicApiExamplePassed=True,
                  consumerTemporaryDirectoryRemoved=not Path(directory).exists(), phases=phases,
                  notes='Fresh project and dependency directory; uses the configured Mooncakes index/cache. No new development API is claimed for 0.2.0.')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as destination:
        json.dump(report, destination, indent=2)
        destination.write('\n')
    print('PASS: fresh Mooncakes 0.2.0 consumer installed, checked and run')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report')
    verify(parser.parse_args().report)
