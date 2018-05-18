# localserver

Helpers for creating test HTTPS servers and clients on localhost.

## Use case

If you're writing a proxy or some sort of routing component, you'll need to
spin up some test servers. In the real world we only speak TLS, never plaintext.
It follows that we'd like to use TLS in our integration tests, since using an
encrypted transport gives us a more realistic setup.

However, dealing with X.509 certificates and keys is kind of a pain. On top of
that, configuring TLS for Go's standard `http.Server` requires some boilerplate.
This project tries to alleviate a little bit of that. We provide functions and
configurable types that reside in memory, speaking HTTP1 and HTTP2 over TLS.

## Example

Create a CA that can sign certs for a host called server1.

```go
ca, err := NewCA(WithDNSNames([]string{"server1"}))
```

Create a signed cert for server1 with the CA object.

```go
cert, err := ca.CreateSignedCert("server1")
```

Create a localhost HTTP2 server on a random high port. We provide a handler that
echoes back our HTTP headers as a map. We provide the CA and the cert created
earlier.

```go
fn := func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(200)
    // Header is an alias: type Header map[string][]string
    data, _ := json.Marshal(r.Header)
    w.Write(data)
}
svr := NewLocalServer(fn, cert, ca)
svr.StartHTTP2() // doesn't block
defer svr.Stop()
```

Now that `svr` is listening on localhost, we can talk to it over HTTPS with a
client that trusts the same CA. Note that since we've spun up our test sever on
a random port, we must use the `AddrPort` method to get the actual port.

```go
client := NewHTTP2Client(ca)
url := fmt.Sprintf("https://server1:%s/", svr.AddrPort())
resp, err := client.Get(url)
```

Importantly, we have to set **server1** as an alias to localhost in **/etc/hosts**,
or otherwise ensure that the name **server1** resolves to localhost. 

