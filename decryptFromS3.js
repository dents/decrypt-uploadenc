const AWS = require('aws-sdk');
const fs = require('fs');
const NodeRSA = require('node-rsa'); // used only to determine private key size
const crypto = require('crypto');
const Busboy = require('busboy');
const path = require('path');
const sanitize = require('sanitize-filename');
const config = require('./decrypt-config.js');

if ('awsCredentials' in config && config.awsCredentials !== null) {
    AWS.config.credentials = new AWS.Credentials(config.awsCredentials);
}

const s3 = new AWS.S3();

const AES_IV_SIZE = 128 / 8;
const AES_KEY_SIZE = 256 / 8;
const AES_BLOCK_SIZE = AES_IV_SIZE;
const HASH_SIZE = 512 / 8;

fs.readFile(config.rsaPrivateKeyPath, (err, privKeyData) => {
    if (err) {
        console.error(`Failed to read RSA private key from ${config.rsaPrivateKeyPath}: ${err}`);
        return;
    }

    const privKey = new NodeRSA(privKeyData);
    console.log(`Using ${privKey.getKeySize()}-bit private key for decryption`);

    const RSA_KEY_SIZE = privKey.getKeySize() / 8;

    new Promise((resolve, reject) => {
        s3.listObjects({
            Bucket: config.s3bucket,
        }, function (err, data) {
            if (err) {
                console.error(err, err.stack);
                reject(err);
                return;
            }

            const filesToDecrypt = [];
            for (let i = 0; i < data.Contents.length; ++i) {
                const fileName = data.Contents[i].Key;

                const dirName = sanitize(stripExt(fileName));
                let localDirStat = null;
                try {
                    localDirStat = fs.statSync(dirName);
                } catch (ex) {
                    if (ex.code == 'ENOENT') {
                        // no dir = we are good to go
                    } else {
                        console.log(ex.code);
                        console.error(ex);
                        continue;
                    }
                }
                if (localDirStat !== null && localDirStat.isDirectory()) {
                    // opportunify to skip existing directory in the future
                }

                filesToDecrypt.push(fileName);
            }
            resolve(filesToDecrypt);
        });
    }).then((filesToDecrypt) => {
        console.log(`Found ${filesToDecrypt.length.toLocaleString()} uploads to process`);
        const decryptSingleFile = (files, index) => {
            if (index >= files.length) {
                console.log('FINISHED');
                return;
            }

            const curName = files[index];
            const fileStream = s3.getObject({
                Bucket: config.s3bucket,
                Key: curName,
            }).createReadStream();

            const decoded = {
                hash: crypto.createHash('sha512'),
                aesIV: Buffer.allocUnsafe(0),
                cryptedKey: Buffer.allocUnsafe(0),
                aesKey: null,
                decipher: null,
                format: null,
                headersLen: null,
                state: 'blank',
                carrying: Buffer.allocUnsafe(0),
                fileName: curName,
                headersData: Buffer.allocUnsafe(0),
                headersParsed: null,
                bodyParser: null,
                filesCreated: [],
                bodyTail: Buffer.allocUnsafe(0),
                tailSize: HASH_SIZE + AES_IV_SIZE,
            };

            fileStream.on('data', (chunk) => {
                if (decoded.decipher === null) {
                    if (chunk.byteLength > 0 && decoded.aesIV.byteLength < AES_IV_SIZE) {
                        const bytesToTake = Math.min(chunk.byteLength, AES_IV_SIZE - decoded.aesIV.byteLength);
                        if (bytesToTake > 0) {
                            decoded.aesIV = Buffer.concat([decoded.aesIV, chunk.slice(0, bytesToTake)]);
                            chunk = chunk.slice(bytesToTake);
                        }
                    }
                    if (chunk.byteLength > 0 && decoded.cryptedKey.byteLength < RSA_KEY_SIZE) {
                        const bytesToTake = Math.min(chunk.byteLength, RSA_KEY_SIZE - decoded.cryptedKey.byteLength);
                        if (bytesToTake > 0) {
                            decoded.cryptedKey = Buffer.concat([decoded.cryptedKey, chunk.slice(0, bytesToTake)]);
                            chunk = chunk.slice(bytesToTake);
                        }
                    }
                    if (decoded.aesKey === null &&
                        decoded.aesIV.byteLength == AES_IV_SIZE &&
                        decoded.cryptedKey.byteLength == RSA_KEY_SIZE) {
                        decoded.aesKey = crypto.privateDecrypt(privKeyData, decoded.cryptedKey);
                        if (decoded.aesKey.length !== AES_KEY_SIZE) {
                            console.error(`Corrupt file ${curName} (invalid key size ${decoded.aesKey.length}), skipping`);
                            fileStream.close();
                            return;
                        }
                        decoded.hash.update(decoded.aesIV);
                        decoded.hash.update(decoded.aesKey);

                        decoded.decipher = crypto.createDecipheriv('aes-256-cbc', decoded.aesKey, decoded.aesIV);
                        decoded.aesKey = Buffer.alloc(decoded.aesKey.length); // no need to keep this
                        decoded.decipher.on('readable', () => {
                            let chunk = decoded.decipher.read();
                            if (chunk && chunk.length > 0) {
                                decoded.carrying = Buffer.concat([decoded.carrying, chunk]);
                            }

                            while (decoded.carrying.length > 0) {
                                if (decoded.state == 'blank' && decoded.carrying.length > 0) {
                                    decoded.format = decoded.carrying.slice(0, 1);
                                    decoded.hash.update(decoded.format);
                                    decoded.carrying = decoded.carrying.slice(1);
                                    decoded.state = 'headerLen';
                                }

                                if (decoded.state == 'headerLen' && decoded.carrying.length >= 4) {
                                    let lengthBuf = decoded.carrying.slice(0, 4);
                                    decoded.headersLen = lengthBuf.readUInt32LE();
                                    decoded.hash.update(lengthBuf);
                                    decoded.carrying = decoded.carrying.slice(4);
                                    decoded.state = 'headers';
                                }

                                if (decoded.state == 'headers') {
                                    let remain = Math.min(decoded.carrying.length, decoded.headersLen - decoded.headersData.byteLength);
                                    if (remain > 0) {
                                        let headerBuf = decoded.carrying.slice(0, remain);
                                        decoded.headersData = Buffer.concat([decoded.headersData, headerBuf]);
                                        decoded.hash.update(headerBuf);
                                        decoded.carrying = decoded.carrying.slice(remain);
                                    }

                                    if (decoded.headersData.byteLength == decoded.headersLen) {
                                        decoded.headersParsed = JSON.parse(decoded.headersData);

                                        let outputDir = sanitize(stripExt(curName));
                                        console.log(` Parsing  ${curName}`);
                                        try {
                                            fs.mkdirSync(outputDir);
                                        } catch (eX) {
                                            if (eX.code !== 'EEXIST') {
                                                console.error(`Failed creating directory: ${eX}`);
                                                return;
                                            }
                                        }

                                        const busboy = new Busboy({
                                            headers: decoded.headersParsed,
                                        });
                                        busboy.on('file', function (fieldname, file, rawFileName, encoding, mime) {
                                            const niceName = sanitize(rawFileName);
                                            const pathA = path.win32.basename(niceName);
                                            const pathB = path.posix.basename(niceName);
                                            const outPath = pathA.length < pathB.length ? pathA : pathB;

                                            const writePath = path.join(outputDir, outPath);
                                            const output = fs.createWriteStream(writePath, {
                                                flags: config.overwriteExisting ? 'w' : 'wx',
                                            });
                                            output.on('error', (err) => {
                                                if (err.code == 'EEXIST' && !config.overwriteExisting) {
                                                    // skipping existing file as requested
                                                } else {
                                                    console.log(`ERROR CREATING FILE: ${err}`);
                                                }
                                            });
                                            console.log(`  Working on ${niceName}`);
                                            file.pipe(output);
                                            decoded.filesCreated.push(writePath);
                                        });
                                        busboy.on('field', function (fieldname, val, fieldnameTruncated, valTruncated, encoding, mimetype) {
                                            console.log(`IGNORED Field [${fieldname}]`);
                                        });
                                        busboy.on('finish', () => {
                                            decoded.bodyParser = null;
                                        });
                                        decoded.bodyParser = busboy;

                                        decoded.state = 'body';
                                    }
                                }

                                if (decoded.state == 'body' && decoded.carrying.byteLength > 0) {
                                    decoded.bodyTail = Buffer.concat([decoded.bodyTail, decoded.carrying]);
                                    decoded.carrying = Buffer.allocUnsafe(0);
                                    let writeLen = decoded.bodyTail.byteLength - decoded.tailSize;
                                    if (writeLen > 0) {
                                        let toWrite = decoded.bodyTail.slice(0, writeLen);
                                        decoded.hash.update(toWrite);
                                        decoded.bodyTail = decoded.bodyTail.slice(writeLen);
                                        // sometimes parser finishes early, ignore any POST data after that
                                        if (decoded.bodyParser !== null) {
                                            decoded.bodyParser.write(toWrite);
                                        }
                                    }
                                }
                            }
                        });

                        decoded.decipher.on('end', () => {
                            if (decoded.bodyParser !== null) {
                                decoded.bodyParser.end();
                            }

                            if (decoded.bodyTail.length != decoded.tailSize) {
                                console.error(`file is corrupt: invalid file trailer ${decoded.bodyTail.length} instead of ${decoded.tailSize}`);
                                wipeCoruptFiles(decoded.filesCreated);
                                return;
                            }

                            let decryptedHash = decoded.bodyTail.slice(0, HASH_SIZE);
                            let decryptedIV = decoded.bodyTail.slice(HASH_SIZE);

                            let calcHash = decoded.hash.digest();

                            if (Buffer.compare(calcHash, decryptedHash) !== 0) {
                                console.error('file is corrupt: hash mismatch');
                                console.log(` calculated: ${calcHash.toString('hex')}`);
                                console.log(`   expected: ${decryptedHash.toString('hex')}`);
                                wipeCoruptFiles(decoded.filesCreated);
                                return;
                            }
                            if (Buffer.compare(decryptedIV, decoded.aesIV) !== 0) {
                                console.log('file is corrupt: iv mismatch');
                                console.log(`    found: ${decoded.aesIV.toString('hex')}`);
                                console.log(` expected: ${decryptedIV.toString('hex')}`);
                                wipeCoruptFiles(decoded.filesCreated);
                                return;
                            }
                            console.log(` Finished ${curName}`);

                            if (config.deleteFromS3OnSuccess) {
                                s3.deleteObject({
                                    Bucket: config.s3bucket,
                                    Key: curName,
                                }, function (err, data) {
                                    if (err) {
                                        console.error(`Failed deleting ${curName} from S3: ${err}`);
                                    } else {
                                        console.log(` Deleted ${curName} from S3`);
                                    }
                                })
                            }
                            // queue up next upload
                            process.nextTick(decryptSingleFile, files, index + 1);
                        });

                        if (chunk.byteLength > 0) {
                            decoded.decipher.write(chunk);
                        }
                    }
                } else {
                    decoded.decipher.write(chunk);
                }
            });
            fileStream.on('end', () => {
                decoded.decipher.end();
            })
            fileStream.read();
        };
        decryptSingleFile(filesToDecrypt, 0);
    }).catch((reason) => {
        console.error(`Failed to read S3 files: ${reason}`);
    });
});

function stripExt(filePath) {
    let targetFile = filePath;
    let fileExt = path.extname(targetFile);
    let baseName = path.basename(targetFile, fileExt);
    return baseName;
}

function wipeCoruptFiles(filesToWipe) {
    filesToWipe.forEach(function (fileName) {
        try {
            fs.unlinkSync(fileName);
        } catch (eX) {
            console.log(`ERROR DELETING CORRUPT FILE ${fileName}`);
        }
    }, this);
}