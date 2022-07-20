# File upload sample (using Gin)

This sample is a web server (using Gin) that accepts uploaded images.  
Clients send images by sending a multipart/form-data POST request to `/upload`, with the image in the `file` field.  
Uploaded images are then stored on disk.  
Using the filetype package, we can reject files that are not images.

All operations on the uploaded file are performed on the stream of data received from the client, so the file is never fully read in memory: you can try this with files of multiple GBs without issues.

To run this example, first start the server with `go run .`

You can test file upload with curl in another terminal:

```sh
curl -F 'file=@image.jpg' \
  "http://localhost:8080/upload"
```
