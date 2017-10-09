let Busboy = require('busboy')
let fs = require('fs');
let path = require('path');

if (process.argv.length < 3) {
    console.log('usage: node parse.js decrypted.txt');
    return;
}

let targetFile = process.argv[2];
let headerFile = stripExt(targetFile) + ".headers.txt";

let headersData = fs.readFileSync(headerFile);
let headersParsed = JSON.parse(headersData);

let outputDir = stripExt(stripExt(targetFile));
console.log(`Writing files to: ${outputDir}`);
try {
    fs.mkdirSync(outputDir);
} catch (eX) {
    if (eX.code !== 'EEXIST') {
        console.error(`Failed creating directory: ${eX}`);
        return;
    }
}

let busboy = new Busboy({
    headers: headersParsed
});
busboy.on('file', function (fieldname, file, filename, encoding, mime) {
    let pathA = path.win32.basename(filename);
    let pathB = path.posix.basename(filename);
    let outPath = pathA.length < pathB.length ? pathA : pathB;

    let output = fs.createWriteStream(path.join(outputDir, outPath), {
        flags: 'wx'
    });
    console.log(`WRITING FILE ${filename}`);
    file.pipe(output);
});
busboy.on('field', function (fieldname, val, fieldnameTruncated, valTruncated, encoding, mimetype) {
    console.log('IGNORED Field [' + fieldname + ']: value: ' + inspect(val));
});
busboy.on('finish', function () {
    console.log('FINISHED!');
});

fs.createReadStream(targetFile, {
    'flags': 'r'
}).pipe(busboy);

function stripExt(filePath) {
    let targetFile = filePath;
    let fileExt = path.extname(targetFile);
    let baseName = path.basename(targetFile, fileExt);
    return baseName;
}