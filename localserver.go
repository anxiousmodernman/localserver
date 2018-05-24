package localserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// LocalServer is a server that can be configured to respond
// with a configurable handler. This is useful for testing.
type LocalServer struct {
	TLS *tls.Config
	Srv *http.Server
	Lis net.Listener
	// we can be configured to collect reads from our net.Listener into a buffer.
	debugBuf *bytes.Buffer
}

func (ls *LocalServer) Debug() string {
	if ls.debugBuf != nil {
		buf := ls.debugBuf.Bytes()
		fmt.Println("len", len(buf))
		return string(buf)
	}
	return "server was not configured with a debug buffer"
}

// CA is a temporary certificate authority suitable for LocalServers.
type CA struct {
	Cert       []byte
	PrivateKey []byte
	conf       *caConfig
}

// NewTLSConfig builds a *tls.Config from a CA and one or more signed certs.
func NewTLSConfig(ca *CA, certs ...*SignedCert) *tls.Config {
	if len(certs) < 1 {
		panic("you must pass at least one SignedCert")
	}

	caCert := x509.NewCertPool()
	if ok := caCert.AppendCertsFromPEM(ca.Cert); !ok {
		panic("building CA cert pool failed")
	}

	var serverCerts []tls.Certificate
	for _, cert := range certs {
		if cert.Cert == nil || cert.PrivateKey == nil {
			panic(fmt.Sprintf("cert and private key must be set: cert: %v key %v", cert.Cert, cert.PrivateKey))
		}
		c, err := tls.X509KeyPair(cert.Cert, cert.PrivateKey)
		if err != nil {
			panic(err)
		}
		serverCerts = append(serverCerts, c)
	}

	conf := &tls.Config{
		RootCAs:      caCert,
		Certificates: serverCerts,
		NextProtos:   []string{"h2"}, // must have this for HTTP2
	}
	return conf
}

type Option func(*LocalServer)

func WithDebugBuffer() Option {
	return func(ls *LocalServer) {
		ls.debugBuf = bytes.NewBuffer(make([]byte, 4<<10))
	}
}

// NewLocalServer builds a LocalServer.
func NewLocalServer(h http.HandlerFunc, cert *SignedCert, ca *CA, opts ...Option) *LocalServer {
	tlsConf := NewTLSConfig(ca, cert)
	lis, err := tls.Listen("tcp", "0.0.0.0:0", tlsConf)
	if err != nil {
		panic(err)
	}

	srv := &http.Server{
		Addr:      lis.Addr().String(),
		Handler:   http.HandlerFunc(h),
		TLSConfig: tlsConf,
	}

	ls := &LocalServer{
		Srv: srv,
		Lis: lis,
		TLS: tlsConf,
	}
	for _, opt := range opts {
		opt(ls)
	}
	return ls
}

// StartHTTP1 starts a LocalServer as an HTTP1 server.
func (ls *LocalServer) StartHTTP1() {
	go func() {
		// This is how you force HTTP1. From the net/http docs:
		// Starting with Go 1.6, the http package has transparent support for the HTTP/2 protocol
		// when using HTTPS. Programs that must disable HTTP/2 can do so by
		// setting Transport.TLSNextProto (for clients) or Server.TLSNextProto
		// (for servers) to a non-nil, empty map.
		empty := make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		ls.Srv.TLSNextProto = empty
		ls.Srv.Serve(ls.Lis)
	}()
}

// StartHTTP2 starts a LocalServer as an HTTP2 server. We rely on Go's net/http package
// using HTTP2 by default, as long as the server uses TLS with the right protocol suite.
func (ls *LocalServer) StartHTTP2() {
	go func() {
		ls.Srv.TLSConfig.NextProtos = []string{http2.NextProtoTLS}
		ls.Srv.TLSConfig.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
		ls.Srv.Serve(ls.Lis)
	}()
}

// Stop stops our HTTP server.
func (ls *LocalServer) Stop() {
	ls.Srv.Shutdown(context.TODO())
}

// AddrPort returns the network address of the LocalServer's net.Listener.
func (ls *LocalServer) AddrPort() string {
	// match port in an address that looks like [::]:12345
	return addrPort(ls.Lis.Addr().String())
}

func addrPort(ipv6Addr string) string {
	re := regexp.MustCompile(`[\[\]:]+(\d+)`)
	matches := re.FindStringSubmatch(ipv6Addr)
	proxyPort := matches[1]
	return proxyPort
}

// NewTestHandler creates a handler that only writes a response code to test requests.
func NewTestHandler(respCode int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(respCode)
	}
}

// CAOption are options for a Certificate Authority.
type CAOption func(*caConfig)

// WithCommonName sets a common name on a CA.
func WithCommonName(cn string) CAOption {
	return func(conf *caConfig) {
		conf.commonName = cn
	}
}

// WithOrganization sets one or more organization names on a CA.
func WithOrganization(orgs []string) CAOption {
	return func(conf *caConfig) {
		conf.organization = orgs
	}
}

// WithDNSNames sets one or more supported DNS names on a CA. If you want to
// issue certs for a specfic DNS/SAN/host name, you must set them with this option.
func WithDNSNames(names []string) CAOption {
	return func(conf *caConfig) {
		conf.dnsNames = names
	}
}

func defaultCAConfigs(conf *caConfig) {
	conf.commonName = "Test Org CA"
	conf.organization = []string{"Test Org"}
	conf.dnsNames = []string{"server1,server2,server3"}
}

type caConfig struct {
	commonName   string
	organization []string
	// SANs
	dnsNames []string
}

// NewCA returns CA
func NewCA(opts ...CAOption) (*CA, error) {

	var conf caConfig
	defaultCAConfigs(&conf)
	for _, opt := range opts {
		opt(&conf)
	}
	// The newly-generated RSA key priv has a public key field as well.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	template := x509.Certificate{
		IsCA:         true,         // true, else we fail at runtime :(
		SerialNumber: serialNumber, // big.Int
		Subject: pkix.Name{
			CommonName:   "Test Org CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(10) * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"server1,server2,server3"},
	}
	// the 3rd param is the "parent" cert; in this case, parent is the same as the 2nd param, so
	// the new cert is self-signed. Priv must always be the private key of the signer.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create cert: %v", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// the root CA has to be distributed to all clients and servers
	newCA := CA{
		Cert:       pemCert,
		PrivateKey: pemKey,
		conf:       &conf,
	}
	return &newCA, nil

}

// A SignedCert can be created by a CA.
type SignedCert struct {
	Cert       []byte
	PrivateKey []byte
}

// CreateSignedCert creates a signed certifictate.
func (ca *CA) CreateSignedCert(name string) (*SignedCert, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: ca.conf.organization,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(10) * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{name},
	}
	blck, rest := pem.Decode(ca.Cert)
	if len(rest) > 0 {
		panic("expected exactly one pem-encoded block")
	}
	parsedCACert, err := x509.ParseCertificate(blck.Bytes)
	if err != nil {
		return nil, err
	}

	blck, rest = pem.Decode(ca.PrivateKey)
	if len(rest) > 0 {
		panic("expected exactly one pem-encoded block")
	}

	parentPriv, err := x509.ParsePKCS1PrivateKey(blck.Bytes)
	if err != nil {
		return nil, err
	}

	// The new signed cert
	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, parsedCACert, &priv.PublicKey, parentPriv)
	if err != nil {
		return nil, fmt.Errorf("create cert: %v", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	signed := SignedCert{pemCert, pemKey}

	return &signed, nil
}

// NewHTTP1Client creates an http1 client that trusts our CA.
func NewHTTP1Client(ca *CA) *http.Client {
	certs := x509.NewCertPool()
	certs.AppendCertsFromPEM(ca.Cert)
	tlsConf := &tls.Config{RootCAs: certs}

	c := &http.Client{}
	tpt := &http.Transport{
		TLSClientConfig: tlsConf,
	}
	c.Transport = tpt
	return c
}

// NewHTTP2Client creates an http2 client that trusts our CA.
func NewHTTP2Client(ca *CA) *http.Client {
	certs := x509.NewCertPool()
	certs.AppendCertsFromPEM(ca.Cert)
	tlsConf := &tls.Config{
		RootCAs:      certs,
		NextProtos:   []string{http2.NextProtoTLS},
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}

	c := &http.Client{}
	tpt := &http2.Transport{
		TLSClientConfig: tlsConf,
	}
	c.Transport = tpt
	return c
}

// GRPCServerImpl ...
type GRPCServerImpl struct {
	Lis net.Listener
	Srv *grpc.Server
}

// ServeGRPC starts a grpc server asyncronously.
func (i *GRPCServerImpl) ServeGRPC() {
	go i.Srv.Serve(i.Lis)
}

// Stop stops our grpc server.
func (i *GRPCServerImpl) Stop() {
	i.Srv.Stop()
}

// Addr returns the full network address of the LocalServer's net.Listener.
func (i *GRPCServerImpl) Addr() string {
	return i.Lis.Addr().String()
}

// AddrPort returns the network port of the LocalServer's net.Listener.
func (i *GRPCServerImpl) AddrPort() string {
	// match port in an address that looks like [::]:12345
	return addrPort(i.Lis.Addr().String())
}

/*
 * Our implementation of generated GRPCServer interface
 */

// Get is our test method for simple unary request-response.
func (i *GRPCServerImpl) Get(ctx context.Context, key *Key) (*Value, error) {
	// echo key as value
	return &Value{key.Key}, nil
}

// PutKVStream is our test method to stream from client to server.
func (i *GRPCServerImpl) PutKVStream(stream GRPC_PutKVStreamServer) error {
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}
	return nil
}

// GetKVStream is our test method to stream from server to client.
func (i *GRPCServerImpl) GetKVStream(key *Key, stream GRPC_GetKVStreamServer) error {
	// send stream of 3
	for _, item := range []string{"1", "2", "3"} {
		if err := stream.Send(&KV{item, item}); err != nil {
			return err
		}
	}
	return nil
}

// NewGRPCServer spins up a server pair on a random port.
// Inspect the Addr field on the returned server to see the port selected
// for the server. The authority parameter is the server hostname.
func NewGRPCServer(ca *CA, cert *SignedCert, authority string) (*GRPCServerImpl, error) {

	tlsCreds := credentials.NewTLS(NewTLSConfig(ca, cert))
	gs := grpc.NewServer(grpc.Creds(tlsCreds))
	// This function is from generated code
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil
	}
	impl := GRPCServerImpl{
		Lis: lis,
		Srv: gs,
	}

	RegisterGRPCServer(gs, &impl)
	return &impl, nil
}

// NewGRPCClientForServer ...
func NewGRPCClientForServer(ca *CA, addr string) (GRPCClient, error) {
	certs := x509.NewCertPool()
	certs.AppendCertsFromPEM(ca.Cert)
	tlsConf := &tls.Config{
		RootCAs:      certs,
		NextProtos:   []string{http2.NextProtoTLS},
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	creds := credentials.NewTLS(tlsConf)

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithTimeout(3*time.Second))
	if err != nil {
		return nil, err
	}
	// ProxyClient, our generated client interface
	c := NewGRPCClient(conn)
	return c, nil
}
