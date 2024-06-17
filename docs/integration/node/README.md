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

### Function to Upload a File with Timestamped Path

```javascript
const { PutObjectCommand } = require("@aws-sdk/client-s3");

const uploadFile = async ({ reader, bucketName, deviceID }) => {
  const now = new Date();
  const year = now.getFullYear();
  const month = now.getMonth() + 1;
  const day = now.getDate();
  const hour = now.getHours();
  const timestamp = now.getTime();

  const key = `${deviceID}/${year}/${month}/${day}/${hour}/${timestamp}.log`;

  const params = {
    Bucket: bucketName,
    Key: key,
    Body: reader,  // Assuming reader is a readable stream or Buffer
  };

  try {
    const data = await client.send(new PutObjectCommand(params));
    console.log(`${key} uploaded successfully.`);
    return data;
  } catch (err) {
    console.error('Error uploading file:', err);
    throw err;
  }
};

// Example usage:
const reader = /* provide your readable stream or Buffer */;
const bucketName = "my-bucket";
const deviceID = "my-device";
await uploadFile({ reader, bucketName, deviceID });
```

### Function to Download Files Based on Time Range

```javascript
const { ListObjectsCommand, GetObjectCommand } = require("@aws-sdk/client-s3");

const downloadFiles = async ({ writer, bucketName, deviceID, startTime, endTime }) => {
  const startPath = `${deviceID}/${startTime.getFullYear()}/${startTime.getMonth() + 1}/${startTime.getDate()}/${startTime.getHours()}`;
  const endPath = `${deviceID}/${endTime.getFullYear()}/${endTime.getMonth() + 1}/${endTime.getDate()}/${endTime.getHours()}`;

  // Determine common prefix
  const commonPrefix = startPath.split('/')
    .filter((part, i) => part === endPath.split('/')[i])
    .join('/');

  try {
    const command = new ListObjectsCommand({
      Bucket: bucketName,
      Prefix: commonPrefix,
    });

    const { Contents } = await client.send(command);

    for (const file of Contents) {
      const obj = await client.send(
        new GetObjectCommand({ Bucket: bucketName, Key: file.Key }),
      );

      writer.write(await obj.Body.transformToByteArray()); // Assuming writer is a writable stream
    }

    console.log('Files downloaded successfully.');
  } catch (err) {
    console.error('Error downloading files:', err);
    throw err;
  }
};

// Example usage:
const writer = /* provide your writable stream */;
const startTime = new Date('2024-06-17T08:00:00Z');
const endTime = new Date('2024-06-17T10:00:00Z');
await downloadFiles({ writer, bucketName: 'my-bucket', deviceID: 'my-device', startTime, endTime });
```

### Explanation:
- **uploadFile**: Uploads a file to S3 with a path structured based on the current timestamp.
- **downloadFiles**: Retrieves files from S3 within a specified time range, using a common prefix to list and download relevant files.
