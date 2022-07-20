# file-type-stream-go

[![Go Reference](https://pkg.go.dev/badge/github.com/italypaleale/file-type-stream-go.svg)](https://pkg.go.dev/github.com/italypaleale/file-type-stream-go)

This library is used to detect the type of a binary file by looking at ["magic numbers"](https://en.wikipedia.org/wiki/Magic_number_(programming)#Magic_numbers_in_files). It is optimized to work with streams, efficiently reading only a small number of bytes in most cases.

This is a port of [sindresorhus/file-type](https://github.com/sindresorhus/file-type) to Go.

> The current version of this package is based on version [17.1.2](https://github.com/sindresorhus/file-type/tree/v17.1.2) of file-type.

## Examples

- [File upload (using Gin)](/examples/gin-file-upload)

## Usage

To use this library, add it to your project with:

```sh
go get github.com/italypaleale/file-type-stream-go
```

You can then import it by adding this to your Go files' imports:

```go
import "github.com/italypaleale/file-type-stream-go/pkg/filetype"
```

### APIs

[Full API reference](https://pkg.go.dev/github.com/italypaleale/file-type-stream-go)

The main package (`github.com/italypaleale/file-type-stream-go/pkg/filetype`) contains 3 main methods:

- Use the `ParseFile` method to detect the type of a file on disk:  

   ```go
   ext, mime, err := filetype.ParseFile("path/to/file")
   ```

- Use the `ParseBytes` method to detect the type of a file contained in a byte slice:  

   ```go
   ext, mime, err := filetype.ParseFile([]byte{/* … */})
   ```

- Use the `ParseStream` method to detect the type of a file from a readable stream:  

   ```go
   var r io.Reader = /* … */
   ext, mime, err := filetype.ParseStream(r)
   ```
