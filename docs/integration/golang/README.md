# S3 Compatible Solutions to Connect Storx Programmatically

Here We have created some examples to connect storx with your application programmatically using golang and s3 utility packages.

## Prerequisites
Before running the code, ensure you have the following prerequisites:

- Credentials created from dashboard.
- Go installed on your machine.

## Security Considerations

It's important to handle access credentials securely. Avoid hardcoding credentials directly into the code. Instead, consider using environment variables or other secure methods for credential management. Additionally, ensure that IAM policies associated with the credentials provide the least privilege necessary for your application's functionality.

## Dependencies in Go
```go
import (
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/awsutil"
    "github.com/aws/aws-sdk-go/aws/credentials"
    "github.com/aws/aws-sdk-go/aws/request"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/s3"
)
```
## Required Values
```go
const (
	AccessKeyID     = "juo7**************24a" // replace with your access key
	SecretAccessKey = "jz3x6tzxx*****************************x7l5mfmvy" // replace with your secretAccessKey
	EndPoint        = "http://localhost:8002" // replace with your endpoint
)
```

## Required Objects
```go
type BucketWithAttribution struct {
	_            struct{}   `type:"structure"`
	CreationDate *time.Time `type:"timestamp"`
	Name         *string    `type:"string"`
	Attribution  *string    `type:"string"`
}

type ListBucketsWithAttributionOutput struct {
	_       struct{}                 `type:"structure"`
	Buckets []*BucketWithAttribution `locationNameList:"Bucket" type:"list"`
	Owner   *s3.Owner                `type:"structure"`
}
```

## 1. Creating a Session

The `CreateSession` function establishes a new session with the S3-compatible solution using provided credentials. Sessions are essential for making requests to S3-compatible services.

```go
func CreateSession() *session.Session {
    creds := credentials.NewStaticCredentials(AccessKeyID, SecretAccessKey, "")
    return session.Must(session.NewSession(&aws.Config{
        Credentials:      creds,
        Region:           aws.String("auto"),
        Endpoint:         aws.String(EndPoint),
        S3ForcePathStyle: aws.Bool(true), // Use path-style access
    }))
}
```

Example:

```go
session := CreateSession()
```

## 2. Creating a Bucket

The `CreateBucket` function creates a new bucket with the given name.

```go
func CreateBucket(bucketName string) {
    ses := CreateSession()
    svc := s3.New(ses)

    _, err := svc.CreateBucket(&s3.CreateBucketInput{
        Bucket: aws.String(bucketName),
    })
    if err != nil {
        panic(err)
    }

    fmt.Println("Bucket created successfully:", bucketName)
}
```

Example:

```go
CreateBucket("mybucket")
```

## 3. Listing Buckets

The `ListBuckets` function retrieves a list of all buckets associated with the account.

```go
func ListBuckets() {
    ses := CreateSession()
    svc := s3.New(ses)

    result, err := svc.ListBuckets(nil)
    if err != nil {
        panic(err)
    }

    fmt.Println("Buckets:")
    for _, bucket := range result.Buckets {
        fmt.Println(*bucket.Name)
    }
}
```

Example:

```go
ListBuckets()
```

## 4. Creating a Folder in a Bucket

The `CreateFolder` function creates a folder (prefix) within an existing bucket.

```go
func CreateFolder(bucketName, path string) {
    ses := CreateSession()
    svc := s3.New(ses)

    _, err := svc.PutObject(&s3.PutObjectInput{
        Bucket: aws.String(bucketName),
        Key:    aws.String(path + "/"),
    })
    if err != nil {
        panic(err)
    }

    fmt.Println("Folder created successfully:", path)
}
```

Example:

```go
CreateFolder("mybucket", "myfolder")
```

## 5. Listing Files in a Bucket

The `ListFilesInBucket` function lists all files (objects) in a given bucket, optionally filtered by a specific path.

```go
func ListFilesInBucket(bucketName, path string) {
    ses := CreateSession()
    svc := s3.New(ses)

    result, err := svc.ListObjects(&s3.ListObjectsInput{
        Bucket: aws.String(bucketName),
        Prefix: aws.String(path),
    })
    if err != nil {
        panic(err)
    }

    fmt.Println("Files in bucket:", bucketName)
    for _, item := range result.Contents {
        fmt.Println(*item.Key)
    }
}
```

Example:

```go
ListFilesInBucket("mybucket", "myfolder")
```

## 6. Uploading a File to a Bucket

The `UploadFile` function uploads a file to a specified location within an bucket.

```go
func UploadFile(bucketName, key, filename string) {
    ses := CreateSession()
    svc := s3.New(ses)

    file, err := os.Open(filename)
    if err != nil {
        panic(err)
    }
    defer file.Close()

    _, err = svc.PutObject(&s3.PutObjectInput{
        Bucket: aws.String(bucketName),
        Key:    aws.String(key),
        Body:   file,
    })
    if err != nil {
        panic(err)
    }

    fmt.Println("File uploaded successfully:", key)
}
```

Example:

```go
UploadFile("mybucket", "myfolder/download.jpeg", "/path/to/local/file.jpeg")
```