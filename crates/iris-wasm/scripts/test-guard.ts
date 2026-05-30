
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import * as guard from "../pkg/iris_wasm.guard.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load test.json
const jsonPath = path.join(__dirname, 'test.json');
const jsonData = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));

// Test
console.log("Testing guard.isPbCom2RawTransaction...");
if (guard.isPbCom2RawTransaction(jsonData)) {
    console.log("SUCCESS: jsonData is a valid PbCom2RawTransaction");
} else {
    console.error("FAILURE: jsonData is NOT a valid PbCom2RawTransaction");
    process.exit(1);
}
