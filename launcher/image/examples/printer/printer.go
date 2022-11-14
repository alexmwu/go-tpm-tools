package main

import (
	"fmt"
	"os"
)

const attestationToken = "/run/container_launcher/attestation_verifier_claims_token"

func main() {
	fmt.Println("printer container ran with: ", os.Args)
	fmt.Println("printer container env:", os.Environ())

	_, err := os.Stat(attestationToken)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("printer OIDC token exists!")
}
