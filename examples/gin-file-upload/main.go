package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/italypaleale/file-type-stream-go/pkg/filetype"
)

/*
This sample is a web server (using Gin) that accepts uploaded images.
Clients send images by sending a multipart/form-data POST request to `/upload`, with the image in the `file` field.
Uploaded images are then stored on disk.
Using the filetype package, we can reject files that are not images.

To run this example, first start the server with `go run .`

You can test file upload with curl:

```sh
curl -F 'file=@image.jpg' \
	"http://localhost:8080/upload"
```
*/

var listen = "127.0.0.1:8080"

func main() {
	router := gin.Default()
	router.POST("/upload", uploadHandler)
	router.Run(listen)
}

func uploadHandler(c *gin.Context) {
	// Get the header of the file that is being uploaded
	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	// Get a readable stream to the file
	file, err := fileHeader.Open()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	// Use a buffer and tee to be able to determine the file type and then write to disk
	buf := &bytes.Buffer{}
	read := io.TeeReader(file, buf)

	// Determine the file type
	ext, mime, err := filetype.ParseStream(read, filetype.ParseOpts{
		// For images, 1KB should be more than enough
		MaxReadBytes: 1024,
	})
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	// Accept images only
	if !strings.HasPrefix(mime, "image/") {
		c.String(http.StatusBadRequest, "Uploaded file is not an image")
		c.Abort()
		return
	}

	// Save the file to disk
	filename := uuid.NewString() + "." + ext
	out, err := os.Create(filename)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	// Because the first bytes of the stream were consumed by the filetype parser, we need to read from the buffer where we copied them, and then finish consuming the stream.
	_, err = io.Copy(out, io.MultiReader(buf, file))
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	c.String(http.StatusOK, filename)
}
