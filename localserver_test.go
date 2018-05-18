package localserver

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
)

func testCAAndCert(t *testing.T) (*CA, *SignedCert) {
	ca, err := NewCA(WithDNSNames([]string{"server1"}))
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	cert, err := ca.CreateSignedCert("server1")
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return ca, cert
}

func TestHTTP1(t *testing.T) {
	ca, cert := testCAAndCert(t)

	// echo our headers
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// Header is an alias:
		// type Header map[string][]string
		data, _ := json.Marshal(r.Header)
		w.Write(data)
	}

	svr := NewLocalServer(fn, cert, ca, WithDebugBuffer())
	svr.StartHTTP1()
	defer svr.Stop()

	url := fmt.Sprintf("https://server1:%s/", svr.AddrPort())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Fruit", "Cherries")

	client := NewHTTP1Client(ca)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	echoedHeaders := make(map[string][]string)
	data, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(data, &echoedHeaders)

	if echoedHeaders["Fruit"][0] != "Cherries" {
		t.Errorf("unexpected response: %v", echoedHeaders)
	}
}

func TestHTTP2(t *testing.T) {
	ca, cert := testCAAndCert(t)

	// echo our headers
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		data, _ := json.Marshal(r.Header)
		w.Write(data)
	}

	svr := NewLocalServer(fn, cert, ca, WithDebugBuffer())
	svr.StartHTTP2()
	defer svr.Stop()

	url := fmt.Sprintf("https://server1:%s/", svr.AddrPort())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Fruit", "Cherries")

	client := NewHTTP2Client(ca)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	echoedHeaders := make(map[string][]string)
	data, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(data, &echoedHeaders)

	if echoedHeaders["Fruit"][0] != "Cherries" {
		t.Errorf("unexpected response: %v", echoedHeaders)
	}
}
