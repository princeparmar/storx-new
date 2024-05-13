# Storx Integration with Node.js

Here we provide examples for integrating Storx with your Node.js application programmatically using the AWS SDK for JavaScript.

## Prerequisites

Before running the code, ensure you have the following prerequisites:

- Node.js installed on your machine.
- Access credentials obtained from the Storx dashboard.

## Security Considerations

Handle access credentials securely. Avoid hardcoding credentials directly into the code. Instead, consider using environment variables or other secure methods for credential management.

## Dependencies

Make sure to install the necessary dependencies using npm:

```bash
npm install @aws-sdk/client-s3
```

## Example Code

Below are functions and examples demonstrating basic operations like creating a bucket, uploading files, listing files, copying files between buckets, downloading files, and cleaning up buckets.

### Function to Create a Bucket

```javascript
const { S3Client, CreateBucketCommand } = require("@aws-sdk/client-s3");

const client = new S3Client(bucketProps);

const createBucket = async (bucketName) => {
  const command = new CreateBucketCommand({ Bucket: bucketName });
  await client.send(command);
  console.log("Bucket created successfully.\n");
  return bucketName;
};

// Example:
createBucket("my-test-bucket");
```

### Function to Upload Files to a Bucket

```javascript
const { PutObjectCommand } = require("@aws-sdk/client-s3");

const uploadFilesToBucket = async ({ bucketName, folderPath }) => {
  console.log(`Uploading files from ${folderPath}\n`);
  const keys = readdirSync(folderPath);
  const files = keys.map((key) => {
    const filePath = `${folderPath}/${key}`;
    const fileContent = readFileSync(filePath);
    return {
      Key: key,
      Body: fileContent,
    };
  });

  for (let file of files) {
    await client.send(
      new PutObjectCommand({
        Bucket: bucketName,
        Body: file.Body,
        Key: file.Key,
      }),
    );
    console.log(`${file.Key} uploaded successfully.`);
  }
};

// Example:
uploadFilesToBucket({ bucketName: "my-bucket", folderPath: "./uploads" });
```

### Function to List Files in a Bucket

```javascript
const { ListObjectsCommand } = require("@aws-sdk/client-s3");

const listFilesInBucket = async ({ bucketName }) => {
  const command = new ListObjectsCommand({ Bucket: bucketName });
  const { Contents } = await client.send(command);
  const contentsList = Contents.map((c) => ` • ${c.Key}`).join("\n");
  console.log("\nHere's a list of files in the bucket:");
  console.log(contentsList + "\n");
};

// Example:
listFilesInBucket({ bucketName: "my-bucket" });
```

### Function to Copy a File from One Bucket to Another

```javascript
const { CopyObjectCommand } = require("@aws-sdk/client-s3");

const copyFileFromBucket = async ( sourceBucket, destinationBucket, sourceKey, destinationKey ) => {
    try {
      const command = new CopyObjectCommand({
        Bucket: destinationBucket,
        CopySource: `${sourceBucket}/${sourceKey}`,
        Key: destinationKey,
      });
      await client.send(command);
      await copyFileFromBucket({ destinationBucket });
    } catch (err) {
      console.error(`Copy error.`);
      console.error(err);

    }
};

// Example:
copyFileFromBucket("source-bucket", "destination-bucket", "source-file.txt", "destination-file.txt");
```

### Function to Download Files from a Bucket

```javascript
const { GetObjectCommand } = require("@aws-sdk/client-s3");

const downloadFilesFromBucket = async ({ bucketName }) => {
  const { Contents } = await client.send(
    new ListObjectsCommand({ Bucket: bucketName }),
  );

  for (let content of Contents) {
    const obj = await client.send(
      new GetObjectCommand({ Bucket: bucketName, Key: content.Key }),
    );
    writeFileSync(
      content.Key,
      await obj.Body.transformToByteArray(),
    );
  }
  console.log("Files downloaded successfully.\n");
};

// Example:
downloadFilesFromBucket({ bucketName: "my-bucket" });
```

### Function to Empty a Bucket

```javascript
const { ListObjectsCommand, DeleteObjectsCommand } = require("@aws-sdk/client-s3");

const emptyBucket = async ({ bucketName }) => {
  const listObjectsCommand = new ListObjectsCommand({ Bucket: bucketName });
  const { Contents } = await client.send(listObjectsCommand);
  const keys = Contents.map((c) => c.Key);

  const deleteObjectsCommand = new DeleteObjectsCommand({
    Bucket: bucketName,
    Delete: { Objects: keys.map((key) => ({ Key: key })) },
  });
  await client.send(deleteObjectsCommand);
  console.log(`${bucketName} emptied successfully.\n`);
};

// Example:
emptyBucket({ bucketName: "my-bucket" });
```

### Function to Delete a Bucket

```javascript
const { DeleteBucketCommand } = require("@aws-sdk/client-s3");

const deleteBucket = async ({ bucketName }) => {
  const command = new DeleteBucketCommand({ Bucket: bucketName });
  await client.send(command);
  console.log(`${bucketName} deleted successfully.\n`);
};

// Example:
deleteBucket({ bucketName: "my-bucket" });
```

Replace placeholders with your actual credentials and bucket names before running the code.
