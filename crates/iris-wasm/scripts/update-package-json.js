const fs = require('fs');
const path = require('path');

const pkgPath = path.join(__dirname, '../pkg/package.json');

try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

    if (!pkg.files) {
        pkg.files = [];
    }

    const fileToAdd = 'iris_wasm.guard.ts';
    if (!pkg.files.includes(fileToAdd)) {
        pkg.files.push(fileToAdd);
        // Also ensure .d.ts is there if not already (wasm-pack usually handles it, but good to be safe)
        // Actually, let's just stick to the request.

        fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
        console.log(`Added ${fileToAdd} to package.json files`);
    } else {
        console.log(`${fileToAdd} already in package.json files`);
    }

} catch (err) {
    console.error('Error updating package.json:', err);
    process.exit(1);
}
