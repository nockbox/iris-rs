
const fs = require('fs');
const path = require('path');

const dtsPath = path.join(__dirname, '../pkg/iris_wasm.d.ts');

try {
    let content = fs.readFileSync(dtsPath, 'utf8');

    // Append missing type definitions
    const missingTypes = `
export type TxId = string;
export type BlockHeight = number;
export type LockTim = Timelock;
`;

    if (!content.includes('export type TxId')) {
        content += missingTypes;
        console.log('Appended missing types to iris_wasm.d.ts');
        fs.writeFileSync(dtsPath, content);
    } else {
        console.log('Types already present in iris_wasm.d.ts');
    }

} catch (err) {
    console.error('Error patching iris_wasm.d.ts:', err);
    process.exit(1);
}
