# Prisma Cloud RQL & API Reference

## Config RQL Examples
```text
# Find all AWS S3 buckets with public read access
config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-s3api-get-bucket-acl' AND json.rule = publicAccessBlockConfiguration.blockPublicAcls is false

# Find unencrypted Azure Storage Accounts
config from cloud.resource where cloud.type = 'azure' AND api.name = 'azure-storage-account-list' AND json.rule = encryption.services.blob.enabled is false
```