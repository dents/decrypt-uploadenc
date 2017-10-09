const crypto = require('crypto');
const fs = require('fs');
const util = require('util');

const IV_SIZE = 128 / 8;
const KEY_SIZE = 256 / 8;
const HASH_SIZE = 512 / 8;
const CRYPTED_SIZE = 2048 / 8;

if (process.argv.length < 3) {
    console.log('usage: node decode.js <encrypted file from S3>');
    return;
}

fs.readFile('private.pem', (err, privKey) => {
    if (err) {
        console.error(`failed to read private.pem key: ${err}`);
        return;
    }

    const fileToDecode = process.argv[2];
    const fileStat = fs.statSync(fileToDecode);
    const cryptedLen = fileStat.size - IV_SIZE - CRYPTED_SIZE;
    fs.open(fileToDecode, 'r', (err, fd) => {
        if (err) {
            console.error(`failed to read file: ${err}`);
            return;
        }

        const hash = crypto.createHash('sha512');

        const iv = new Buffer(IV_SIZE);
        const ivRead = fs.readSync(fd, iv, 0, IV_SIZE, null);
        if (ivRead != IV_SIZE) {
            console.error('failed to read iv');
            return;
        }
        hash.update(iv);

        const cryptedKey = new Buffer(CRYPTED_SIZE);
        const cryptedKeyRead = fs.readSync(fd, cryptedKey, 0, CRYPTED_SIZE, null);
        if (cryptedKeyRead != CRYPTED_SIZE) {
            console.error('filed to read crypted key');
            return;
        }

        const key = crypto.privateDecrypt(privKey, cryptedKey);
        if (key.length != KEY_SIZE) {
            console.error(`invalid key size ${key.length}`);
            return;
        }
        hash.update(key);

        let decoded = {
            format: null,
            headersLen: null,
            state: 'blank',
            carrying: new Buffer(0),
            fileName: fileToDecode,
            outHeaders: fs.createWriteStream(`${fileToDecode}.headers.txt`, {
                flags: 'w',
            }),
            headersWritten: 0,
            outBody: fs.createWriteStream(`${fileToDecode}.txt`, {
                'flags': 'w',
            }),
            bodyWritten: 0,
            bodyTail: new Buffer(0),
            tailSize: HASH_SIZE + IV_SIZE,
        };

        let decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        decipher.on('readable', () => {
            let chunk = decipher.read();
            if (chunk && chunk.length > 0) {
                decoded.carrying = Buffer.concat([decoded.carrying, chunk]);
            }

            while (decoded.carrying.length > 0) {
                if (decoded.state == 'blank' && decoded.carrying.length > 0) {
                    decoded.format = decoded.carrying.slice(0, 1);
                    hash.update(decoded.format);
                    decoded.carrying = decoded.carrying.slice(1);
                    decoded.state = 'headerLen';
                }

                if (decoded.state == 'headerLen' && decoded.carrying.length >= 4) {
                    let lengthBuf = decoded.carrying.slice(0, 4);
                    decoded.headersLen = lengthBuf.readUInt32LE();
                    hash.update(lengthBuf);
                    decoded.carrying = decoded.carrying.slice(4);
                    decoded.state = 'headers';
                }

                if (decoded.state == 'headers') {
                    let remain = Math.min(decoded.carrying.length, decoded.headersLen - decoded.headersWritten);
                    if (remain > 0) {
                        let headerBuf = decoded.carrying.slice(0, remain);
                        decoded.outHeaders.write(headerBuf);
                        hash.update(headerBuf);
                        decoded.carrying = decoded.carrying.slice(remain);
                        decoded.headersWritten += remain;
                    }

                    if (decoded.headersWritten == decoded.headersLen) {
                        decoded.outHeaders.end();
                        decoded.outHeaders.close();
                        decoded.state = 'body';
                    }
                }

                if (decoded.state == 'body' && decoded.carrying.length > 0) {
                    decoded.bodyTail = Buffer.concat([decoded.bodyTail, decoded.carrying]);
                    decoded.carrying = new Buffer(0);
                    let writeLen = decoded.bodyTail.length - decoded.tailSize;
                    if (writeLen > 0) {
                        let toWrite = decoded.bodyTail.slice(0, writeLen);
                        decoded.bodyTail = decoded.bodyTail.slice(writeLen);
                        decoded.outBody.write(toWrite);
                        hash.update(toWrite);
                    }
                }
            }
        });

        decipher.on('end', () => {
            decoded.outBody.on('finish', () => {
                if (decoded.bodyTail.length != decoded.tailSize) {
                    console.error(`file is corrupt: invalid file trailer ${decoded.bodyTail.length} instead of ${decoded.tailSize}`);
                    wipeCoruptFiles(decoded.fileName);
                    return;
                }

                let decodedHash = decoded.bodyTail.slice(0, HASH_SIZE);
                let decodedIV = decoded.bodyTail.slice(HASH_SIZE);

                let calcHash = hash.digest();

                if (Buffer.compare(calcHash, decodedHash) !== 0) {
                    console.error('file is corrupt: hash mismatch');
                    console.log(` calculated: ${calcHash.toString('hex')}`);
                    console.log(`   expected: ${decodedHash.toString('hex')}`);
                    wipeCoruptFiles(decoded.fileName);
                    return;
                }
                if (Buffer.compare(decodedIV, iv) !== 0) {
                    console.log('file is corrupt: iv mismatch');
                    console.log(`    found: ${iv.toString('hex')}`);
                    console.log(` expected: ${decodedIV.toString('hex')}`);
                    wipeCoruptFiles(decoded.fileName);
                    return;
                }
                console.log('FINISHED DECRYPTING');
            });

            decoded.outBody.end();
        });

        let cryptedStream = fs.createReadStream(null, {
            'fd': fd
        });
        cryptedStream.pipe(decipher);
    });
});

function wipeCoruptFiles(baseName) {
    fs.unlinkSync(`${baseName}.txt`);
    fs.unlinkSync(`${baseName}.headers.txt`);
}