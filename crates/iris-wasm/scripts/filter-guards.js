const fs = require('fs');

const inputFile = process.argv[2];
const outputFile = process.argv[3];
const excludes = ['InitInput', 'InitOutput', 'SyncInitInput', 'ExtendedKey'];
const guardsToRemove = [
    'isReadableStreamType',
    'isInitInput',
    'isInitOutput',
    'isSyncInitInput',
    'isZBase',
    'isZSet',
    'isZSetEntry',
    'isZMap',
    'isZMapEntry'
];

let content = fs.readFileSync(inputFile, 'utf8');

let lines = content.split('\n');
let newLines = [];
let skip = false;
let braceCount = 0;
let insideGuard = false;
let currentGuardName = '';

for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    // Modify import to be import type to avoid runtime errors for non-existent value exports
    if (line.trim().startsWith('import {')) {
        line = line.replace('import {', 'import type {');
    }

    // Also fix the import to include .js extension for ESM compatibility
    line = line.replace('from "./iris_wasm"', 'from "./iris_wasm.js"');

    // Check if we are starting a guard function that needs to be removed
    let matchedGuardToRemove = false;
    for (const guardName of guardsToRemove) {
        if (line.trim().startsWith(`export function ${guardName}(`)) {
            insideGuard = true;
            currentGuardName = guardName;
            braceCount = 0;
            // Count braces in this line
            for (const char of line) {
                if (char === '{') braceCount++;
                if (char === '}') braceCount--;
            }
            matchedGuardToRemove = true;
            break;
        }
    }

    if (matchedGuardToRemove) {
        continue; // Skip this line as it's the start of a guard to remove
    }

    if (insideGuard) {
        // Count braces to find end of block
        for (const char of line) {
            if (char === '{') braceCount++;
            if (char === '}') braceCount--;
        }

        if (braceCount === 0) {
            insideGuard = false;
            currentGuardName = '';
        }
        continue; // Skip this line as it's part of a guard to remove
    }

    // Check if we start an excluded function (original logic)
    let matchedExclude = false;
    for (const exclude of excludes) {
        if (line.trim().startsWith(`export function is${exclude}(`)) {
            skip = true;
            matchedExclude = true;
            braceCount = 0;
            // Count braces in this line
            for (const char of line) {
                if (char === '{') braceCount++;
                if (char === '}') braceCount--;
            }
            break;
        }
    }

    if (matchedExclude) continue;

    if (skip) {
        // Count braces to find end of block
        for (const char of line) {
            if (char === '{') braceCount++;
            if (char === '}') braceCount--;
        }

        if (braceCount === 0) {
            skip = false;
        }
        continue;
    }

    newLines.push(line);
}

// Append manual generic guard implementations
const genericGuards = `
export function isZBase<E>(obj: unknown, isE: (e: unknown) => e is E): obj is ZBase<E> {
    return Array.isArray(obj) && obj.every(isE);
}

export function isZSetEntry<T>(obj: unknown, isT: (t: unknown) => t is T): obj is ZSetEntry<T> {
    return isT(obj);
}

export function isZSet<T>(obj: unknown, isT: (t: unknown) => t is T): obj is ZSet<T> {
    return isZBase(obj, (e): e is ZSetEntry<T> => isZSetEntry(e, isT));
}

export function isZMapEntry<K, V>(obj: unknown, isK: (k: unknown) => k is K, isV: (v: unknown) => v is V): obj is ZMapEntry<K, V> {
    return Array.isArray(obj) && obj.length === 2 && isK(obj[0]) && isV(obj[1]);
}

export function isZMap<K, V>(obj: unknown, isK: (k: unknown) => k is K, isV: (v: unknown) => v is V): obj is ZMap<K, V> {
    if (!Array.isArray(obj)) return false;
    return obj.every((entry) => isZMapEntry(entry, isK, isV));
}
`;

newLines.push(genericGuards);

// Write the result
fs.writeFileSync(outputFile, newLines.join('\n'));
