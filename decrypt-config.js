module.exports = {
    // note: remove this block to use AWS roles or any other auth methods mentioned in AWS SDK
    awsCredentials: {
        accessKeyId: '---aws-key---',
        secretAccessKey: '---aws-secret---',
    },

    // the AWS S3 bucket that uploadenc sends files to
    s3bucket: '---aws-bucket---',

    // private.pem generated during uploadenc setup
    rsaPrivateKeyPath: 'private.pem',

    overwriteExisting: false,

    deleteFromS3OnSuccess: true,
};