#!/bin/bash
# Run tests on all targets for mb-getrandom
set -e

echo "=== Native tests ==="
moon test --target native

echo "=== JS tests ==="
moon test --target js

echo "=== WASM-GC tests (custom harness) ==="
moon test --target wasm-gc --build-only
node test/run_wasm_gc_test.mjs

echo "=== All targets passed ==="
