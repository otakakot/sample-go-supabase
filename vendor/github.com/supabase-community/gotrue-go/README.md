# gotrue-go

![example branch parameter](https://github.com/supabase-community/gotrue-go/actions/workflows/test.yaml/badge.svg?branch=main)
[![codecov](https://codecov.io/gh/supabase-community/gotrue-go/branch/main/graph/badge.svg?token=JQQJKETMRX)](https://codecov.io/gh/supabase-community/gotrue-go)
![GitHub](https://img.shields.io/github/license/supabase-community/gotrue-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/supabase-community/gotrue-go.svg)](https://pkg.go.dev/github.com/supabase-community/gotrue-go)


A Golang client library for the [Supabase GoTrue](https://github.com/supabase/gotrue) API.

> ⚠️ Using [`netlify/gotrue`](https://github.com/netlify/gotrue)?
>
> The types in this library assume you are interacting with a Supabase GoTrue server. It is very unlikely to work with a Netlify GoTrue server.

For more information about the Supabase fork of GoTrue, [check out the project here](https://github.com/supabase/gotrue).

## Project status

This library is a pre-release work in progress. It has not been thoroughly tested, and the API may be subject to breaking changes, and so it should not be used in production.

The endpoints for SSO SAML are not tested and `POST /sso/saml/acs` does not provide request and response types. If you need additional support for SSO SAML, please create an issue or a pull request.

## Quick start

### Install

```sh
go get github.com/supabase-community/gotrue-go
```

### Usage
```go
package main

import "github.com/supabase-community/gotrue-go"

const (
    projectReference = "<your_supabase_project_reference>"
    apiKey = "<your_supabase_anon_key>"
)

func main() {
    // Initialise client
    client := gotrue.New(
        projectReference,
        apiKey,
    )

    // Log in a user (get access and refresh tokens)
    resp, err := client.Token(gotrue.TokenRequest{
        GrantType: "password",
        Email: "<user_email>",
        Password: "<user_password>",
    })
    if err != nil {
        log.Fatal(err.Error())
    }
    log.Printf("%+v", resp)
}
```

## Options

The client can be customized with the options below.

In all cases, **these functions return a copy of the client**. To use the configured value, you must use the returned client. For example:

```go
client := gotrue.New(
    projectRefernce,
    apiKey,
)

token, err := client.Token(gotrue.TokenRequest{
        GrantType: "password",
        Email: email,
        Password: password,
})
if err != nil {
    // Handle error...
}

authedClient := client.WithToken(
    token.AccessToken,
)
user, err := authedClient.GetUser()
if err != nil {
    // Handle error...
}
```

### WithToken
```go
func (*Client) WithToken(token string) *Client
```

Returns a client that will use the provided token in the `Authorization` header on all requests.

### WithCustomGoTrueURL
```go
func (*Client) WithCustomGoTrueURL(url string) *Client
```

Returns a client that will use the provided URL instead of `https://<project_ref>.supabase.com/auth/v1/`. This allows you to use the client with your own deployment of the GoTrue server without relying on a Supabase-hosted project.

### WithClient
```go
func (*Client) WithClient(client http.Client) *Client
```

By default, the library uses a default http.Client. If you want to configure your own, pass one in using `WithClient` and it will be used for all requests made with the returned `*gotrue.Client`.

## Testing

> You don't need to know this stuff to use the library

The library is tested against a real GoTrue server running in a docker image. This also requires a postgres server to back it. These are configured using docker compose.

To run these tests, simply `make test`.

To interact with docker compose, you can also use `make up` and `make down`.

## Differences from gotrue-js

Prior users of [`gotrue-js`](https://github.com/supabase/gotrue-js) may be familiar with its subscription mechanism and session management - in line with its ability to be used as a client-side authentication library, in addition to use on the server.

As Go is typically used on the backend, this library acts purely as a convenient wrapper for interacting with a GoTrue server. It provides no session management or subscription mechanism.

