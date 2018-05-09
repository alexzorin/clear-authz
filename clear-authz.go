package main

import (
	"bufio"
	"crypto"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/net/context"

	"golang.org/x/crypto/acme"
	"gopkg.in/square/go-jose.v2"
)

var (
	pattern *regexp.Regexp
)

func main() {
	v1Server := os.Getenv("CLEAR_AUTHZ_SERVER")
	if v1Server == "" {
		v1Server = "acme-v01.api.letsencrypt.org"
	}

	var keyPath string

	if len(os.Args) < 2 {
		files, err := filepath.Glob("/etc/letsencrypt/accounts/" + v1Server + "/directory/*/private_key.json")
		if err != nil {
			log.Fatalf("Failed to look in Certbot directory path: %v", err)
		}

		if len(files) == 0 {
			log.Fatalf("Could not find any Certbot private keys for directory %s", v1Server)
		}
		keyPath = files[0]
	} else {
		keyPath = os.Args[1]
	}
	log.Printf("Using %s for private key for %s", keyPath, v1Server)

	pattern := regexp.MustCompile("https://" + regexp.QuoteMeta(v1Server) + "/acme/authz/[a-zA-Z0-9_-]+")

	pkBuf, err := ioutil.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}

	var k jose.JSONWebKey
	if err := k.UnmarshalJSON(pkBuf); err != nil {
		panic(err)
	}

	sc := bufio.NewScanner(os.Stdin)
	m := map[string]struct{}{}
	for sc.Scan() {
		urls := pattern.FindAllString(sc.Text(), -1)
		if len(urls) == 0 {
			continue
		}
		for _, u := range urls {
			m[u] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		panic(err)
	}

	log.Printf("Checking %d authzs to see if they are pending ...", len(m))

	cl := &acme.Client{
		Key: k.Key.(crypto.Signer),
	}

	for authURL := range m {
		authz, err := cl.GetAuthorization(context.Background(), authURL)
		if err != nil {
			if !strings.Contains(err.Error(), "urn:acme:error:malformed: Expired authorization") {
				log.Printf("Failed to fetch authz %s: %v", authURL, err)
			}
			continue
		}

		if authz.Status != "pending" {
			continue
		}

		log.Printf("Found pending authz at %s, will accept first challenge", authURL)

		resp, err := cl.Accept(context.Background(), authz.Challenges[0])
		log.Printf("Accepted challenge: %+v %+v", resp, err)
	}
}
