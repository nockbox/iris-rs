const fs = require('fs');

const dtsIn = process.argv[2];
const dtsOut = process.argv[3];
const guardIn = process.argv[4];
const guardOut = process.argv[5];
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

let content = fs.readFileSync(guardIn, 'utf8');

let lines = content.split('\n');
let newLines = [];
let skip = false;
let braceCount = 0;
let insideGuard = false;
let currentGuardName = '';

let dtsContent = fs.readFileSync(dtsIn, 'utf8');
const tagTypeRegex = /export type ([A-Za-z0-9_]+) = string \| \{\s*__tag_[a-z0-9_]+:\s*undefined\s*\};/g;
const taggedTypes = new Set();
let match;
while ((match = tagTypeRegex.exec(dtsContent)) !== null) {
    taggedTypes.add(match[1]);
}

// Nockchain base58 atoms do not have 1-padding, so we need to use a different regex.
const nockchainBase58Regex = "/^[A-HJ-NP-Za-km-z2-9][A-HJ-NP-Za-km-z1-9]*$/";

// TODO: check string length for these
const customGuardImplementations = {
    'Nicks': 'return (typeof typedObj === "string" && /^[0-9]*$/.test(typedObj))',
    'Digest': `return (typeof typedObj === "string" && ${nockchainBase58Regex}.test(typedObj))`,
    'CheetahPoint': `return (typeof typedObj === "string" && ${nockchainBase58Regex}.test(typedObj))`,
    // These are mere type aliases, but we need to handle them all the same.
    'TxId': `return (typeof typedObj === "string" && ${nockchainBase58Regex}.test(typedObj))`,
    'PublicKey': `return (typeof typedObj === "string" && ${nockchainBase58Regex}.test(typedObj))`,
};

let insideTaggedGuard = false;
let currentTaggedGuardName = '';

// Re-write dtsContent and save it
if (taggedTypes.size > 0) {
    console.log("Replacing", taggedTypes);
    const dtsReplaced = dtsContent.replace(
        /export type ([A-Za-z0-9_]+) = string \| \{\s*__tag_[a-z0-9_]+:\s*undefined\s*\};/g,
        'export type $1 = string;'
    );
    fs.writeFileSync(dtsOut, dtsReplaced);
} else {
    fs.writeFileSync(dtsOut, dtsContent);
}

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

    // Downgrade type cast to any for compatibility
    if (line.trim().startsWith('const typedObj = obj as')) {
        line = line.replace(/as .+$/, 'as any');
    }

    if (!insideTaggedGuard) {
        let matchedTaggedGuard = false;
        for (const typeName of Array.from(taggedTypes).concat(Object.keys(customGuardImplementations))) {
            if (line.trim().startsWith(`export function is${typeName}(`)) {
                console.log("Patching", typeName);
                if (!customGuardImplementations[typeName]) {
                    throw new Error(`Missing custom guard implementation for tagged type: ${typeName}`);
                }
                insideTaggedGuard = true;
                currentTaggedGuardName = typeName;
                braceCount = 0;
                for (const char of line) {
                    if (char === '{') braceCount++;
                    if (char === '}') braceCount--;
                }
                matchedTaggedGuard = true;

                // Add the start of the function and the custom body
                newLines.push(line);
                newLines.push(`    const typedObj = obj as any;`);
                newLines.push(`    ${customGuardImplementations[typeName]};`);
                break;
            }
        }

        if (matchedTaggedGuard) continue;
    }

    if (insideTaggedGuard) {
        for (const char of line) {
            if (char === '{') braceCount++;
            if (char === '}') braceCount--;
        }

        if (braceCount === 0) {
            insideTaggedGuard = false;
            newLines.push(line); // push the closing brace
            currentTaggedGuardName = '';
        }
        continue; // skip the original body lines
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
fs.writeFileSync(guardOut, newLines.join('\n'));
