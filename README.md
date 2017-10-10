# decrypt-uploadenc
  Decrypts files created by [uploadenc](https://github.com/dents/uploadenc).

Usage:
* private.pem needs to be present in directory (see [uploadenc](https://github.com/dents/uploadenc) for generation instructions)
* AWS S3 credentials need to be either included in [decrypt-config.js](decrypt-config.js) or anywhere the [AWS SDK](http://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/getting-started-nodejs.html#getting-started-nodejs-configure-keys) will see them. When using AWS instance roles, set awsCredentials to null in [decrypt-config.js](decrypt-config.js) and the AWS SDK will automatically take care of everything. Although the whole point of this project is to keep private keys off AWS, so the decryption program should be run outside of the cloud.
* This will stream files from S3, decrypt and process them on the fly, generating files on local disk:
  * `node decryptFromS3.js`

By default the encrypted blobs are deleted from S3 after successful decryption. See [decrypt-config.js](decrypt-config.js) to turn that off.

Encrypted files are signed with SHA512 so any corruption can be detected, however they do not contain any recovery information. If there is corruption, the affected encrypted file needs to be downloaded from S3 again. The only place corruption could reasonably come from is an ISP injecting garbage, for example when using a cruise ship wifi.
