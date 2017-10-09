# decrypt-uploadenc
  Decrypts files created by [uploadenc](https://github.com/dents/uploadenc).

Usage:
* private.pem needs to be present in directory (see [uploadenc](https://github.com/dents/uploadenc) for generation instructions)
* Download a file that uploadenc wrote to S3, in this example we call it encrypted.bin
* First, decrypt and unpack it:
  * `node decrypt.js encrypted.bin`
* This creates two text files describing the original request. Now, parse it to get uploaded files out:
  * `node parse.js encrypted.bin.txt`
* This will create a directory called encrypted.bin and put any files it finds inside it.

If everything went fine, encrypted.bin can be deleted from AWS and forgotten. Encrypted files are signed with SHA512 so any corruption can be detected, however they do not contain any recovery information. If there is corruption, the affected encrypted file needs to be downloaded from S3 again. The only place it could reasonably come from is an ISP injecting garbage, for example when using a cruise ship wifi.
