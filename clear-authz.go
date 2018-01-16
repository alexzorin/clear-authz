package main

import (
	"bufio"
	"crypto"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"golang.org/x/net/context"

	"golang.org/x/crypto/acme"
	"gopkg.in/square/go-jose.v2"
)

var (
	pattern = regexp.MustCompile(`https://acme-v01\.api\.letsencrypt\.org/acme/authz/[a-zA-Z0-9_-]+`)
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: clear-authz path-to-certbot-private_key.json")
		os.Exit(1)
	}

	pkBuf, err := ioutil.ReadFile(os.Args[1])
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

	fmt.Printf("Checking %d authzs to see if they are pending ...\n", len(m))

	cl := &acme.Client{
		Key: k.Key.(crypto.Signer),
	}

	for authURL := range m {
		authz, err := cl.GetAuthorization(context.Background(), authURL)
		if err != nil {
			if !strings.Contains(err.Error(), "urn:acme:error:malformed: Expired authorization") {
				fmt.Printf("Failed to fetch authz %s: %v\n", authURL, err)
			}
			continue
		}

		if authz.Status != "pending" {
			continue
		}

		fmt.Printf("Found pending authz at %s, will accept first challenge\n", authURL)

		resp, err := cl.Accept(context.Background(), authz.Challenges[0])
		fmt.Printf("Accepted challenge: %+v %+v\n", resp, err)
	}
}
