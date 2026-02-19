#!/bin/bash
set -e

# 1. Build WASM
if [ -z "${NO_PACK:-}" ]; then
    echo "Building WASM..."
    rm -rf pkg
    wasm-pack build --target web --out-dir pkg --scope nockbox
fi

# 2. Filter and Patch
echo "Patching Type Definitions..."
node scripts/patch-dts.js

# 3. Generate Guards
echo "Generating Type Guards..."
npx ts-auto-guard pkg/iris_wasm.d.ts --export-all --project tsconfig.json --guard-file-name guard

# 4. Post-process Guards
echo "Filtering Guards..."
node scripts/filter-guards.js pkg/iris_wasm.guard.ts pkg/iris_wasm.guard.ts

# 5. Update package.json
echo "Updating package.json..."
node scripts/update-package-json.js