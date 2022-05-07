# Jwt Library

Jwt is a library written in Go (Golang).

Jwt is implemented using HS256 algorithm.

## Contents

- [Jwt Library](#jwt-library)
  - [Installation](#installation)
  - [Quick start](#quick-start)

## Installation

To install jwt package, you need to install Go and set your Go workspace first.

1. You first need [Go](https://golang.org/) installed (**version 1.7+ is required**), then you can use the below Go command to install Jwt.

    ```sh
    go get github.com/zsaw/jwt
    ```

2. Import it in your code:

    ```go
    import "github.com/zsaw/jwt"
    ```

## Quick start

```go
package main

import (
    "fmt"
    "os"
    "time"

    "github.com/zsaw/jwt"
)

const SECRET = "NTDSCPPSYX"

func main() {
    token := jwt.New(10*time.Second, "", "", "", []byte(SECRET))
    fmt.Printf("token: %s\n", token)

    newToken, err := jwt.Refresh(token, 10*time.Second, []byte(SECRET))
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    fmt.Printf("new token: %s\n", newToken)

    if err := jwt.VerifySignature(newToken, []byte(SECRET)); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    fmt.Println("verify signature passed")
}
```
