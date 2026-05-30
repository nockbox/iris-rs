import * as fs from "node:fs";
import * as path from "node:path";
import * as repl from "node:repl";
import * as url from "node:url";

// IMPORTANT: import the actual wasm-pack JS entry
import init, * as wasm from "../pkg/iris_wasm"; // adjust if needed
import * as guard from "../pkg/iris_wasm.guard";

async function main() {
  // Find the .wasm next to the JS entry
  const here = path.dirname(url.fileURLToPath(import.meta.url));
  const wasmPath = path.join(here, "../pkg", "iris_wasm_bg.wasm");

  const bytes = fs.readFileSync(wasmPath);

  // wasm-pack glue usually supports init(bytes) OR initSync(bytes).
  // Try init(bytes) first (works for bundler/web targets too).
  await (init as any)(bytes);

  // expose to the REPL
  (globalThis as any).wasm = wasm;
  (globalThis as any).guard = guard;

  const replServer = repl.start({ prompt: "wasm> " });

  process.on("uncaughtException", (err: any) => {
    console.error("Uncaught Exception:", err);
  });

  process.on("unhandledRejection", (reason: any, promise: any) => {
    console.error("Unhandled Rejection:", reason);
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
