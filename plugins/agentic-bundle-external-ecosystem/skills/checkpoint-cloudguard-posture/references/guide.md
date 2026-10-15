# Check Point CloudGuard GSL Reference

## GSL Rule Examples
```text
# S3 Bucket must enforce server-side encryption
S3Bucket should have encryption.serverSideEncryptionConfiguration.rules contain [ applyServerSideEncryptionByDefault.sseAlgorithm in ('AES256', 'aws:kms') ]

# EC2 Security Group must not allow open SSH to 0.0.0.0/0
SecurityGroup should not have inboundRules contain [ port=22 and scope='0.0.0.0/0' ]
```