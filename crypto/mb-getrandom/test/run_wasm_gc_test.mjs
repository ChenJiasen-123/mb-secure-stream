#!/usr/bin/env node
// Custom test harness for running mb-getrandom wasm-gc tests with crypto host imports.
// Usage: node test/run_wasm_gc_test.mjs
//
// moonrun doesn't support custom host imports, so we instantiate the WASM module
// ourselves and provide the "crypto" namespace that getrandom_wasm.mbt expects.

import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Paths to the test WASM files (built by `moon build --target wasm-gc`)
const buildDir = path.join(
  __dirname,
  "../_build/wasm-gc/debug/test/lib"
);

const wasmFiles = [
  "lib.blackbox_test.wasm",
  "lib.internal_test.wasm",
];

// Read test info to know which tests to run
function loadTestInfo(name) {
  const infoFile = name.includes("blackbox")
    ? "__blackbox_test_info.json"
    : "__internal_test_info.json";
  const raw = readFileSync(path.join(buildDir, infoFile), "utf-8");
  return JSON.parse(raw);
}

// Build the import object that the WASM module needs
function createImportObject() {
  const exceptionTag = new WebAssembly.Tag({ parameters: [] });

  return {
    exception: {
      tag: exceptionTag,
      throw: () => {
        throw new WebAssembly.Exception(exceptionTag, []);
      },
    },

    crypto: {
      newUint8Array: (len) => new Uint8Array(len),
      getRandomValues: (buf) => {
        webcrypto.getRandomValues(buf);
      },
      readByte: (buf, idx) => buf[idx],
    },

    spectest: {
      print_char: (ch) => process.stdout.write(String.fromCharCode(ch)),
    },

    __moonbit_fs_unstable: {
      // String reading helpers used by the test driver for filenames
      begin_read_string: (() => {
        let current = "";
        let pos = 0;
        return {
          begin: (s) => {
            current = s;
            pos = 0;
            return current.length;
          },
          read: () => {
            if (pos < current.length) return current.charCodeAt(pos++);
            return -1;
          },
          finish: () => {
            current = "";
            pos = 0;
          },
        };
      })(),
    },
  };
}

async function runTests() {
  let totalTests = 0;
  let passed = 0;
  let failed = 0;

  for (const wasmFile of wasmFiles) {
    const wasmPath = path.join(buildDir, wasmFile);

    let wasmBytes;
    try {
      wasmBytes = readFileSync(wasmPath);
    } catch {
      // No test file for this variant, skip
      continue;
    }

    const testInfo = loadTestInfo(wasmFile);
    const allTests = testInfo.no_args_tests || testInfo.tests || {};

    // Collect all tests across all source files
    const testEntries = [];
    for (const [filename, tests] of Object.entries(allTests)) {
      for (const t of tests) {
        testEntries.push({ filename, ...t });
      }
    }

    if (testEntries.length === 0) continue;

    const importObj = createImportObject();

    // Wire up the string reading helpers properly
    const strHelper = importObj.__moonbit_fs_unstable.begin_read_string;
    importObj.__moonbit_fs_unstable = {
      begin_read_string: (s) => strHelper.begin(s),
      string_read_char: () => strHelper.read(),
      finish_read_string: () => strHelper.finish(),
    };

    const module = new WebAssembly.Module(wasmBytes, {
      builtins: ["js-string"],
      importedStringConstants: "_",
    });
    const instance = new WebAssembly.Instance(module, importObj);

    const { exports } = instance;

    console.log(`\nRunning ${testEntries.length} tests from ${wasmFile}:`);

    for (const t of testEntries) {
      totalTests++;
      const testName = t.name || `${t.filename}::test#${t.index}`;
      try {
        exports.moonbit_test_driver_internal_execute(t.filename, t.index);
        passed++;
        console.log(`  PASS: ${testName}`);
      } catch (e) {
        failed++;
        console.error(`  FAIL: ${testName}`);
        if (e instanceof WebAssembly.Exception) {
          console.error(`    MoonBit test assertion failed`);
        } else {
          console.error(`    ${e.message || e}`);
        }
      }
    }

    if (exports.moonbit_test_driver_finish) {
      exports.moonbit_test_driver_finish();
    }
  }

  console.log(`\nResults: ${passed}/${totalTests} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((e) => {
  console.error("Test harness error:", e);
  process.exit(1);
});
