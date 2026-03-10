const fs = require('fs');
const path = require('path');

const inputFile = process.argv[2];
const outputFile = process.argv[3];

try {
    let dtsContent = fs.readFileSync(inputFile, 'utf8');

    // Append missing type definitions
    const missingTypes = `
export type TxId = Digest;
export type BlockHeight = number | { __tag_block_height: undefined };
export type LockTim = Timelock;
`;

    if (!dtsContent.includes('export type TxId')) {
        dtsContent += missingTypes;
        console.log('Appended missing types to ' + outputFile);
    } else {
        console.log('Types already present in ' + outputFile);
    }

    fs.writeFileSync(outputFile, dtsContent);

} catch (err) {
    console.error('Error patching iris_wasm.d.ts:', err);
    process.exit(1);
}
