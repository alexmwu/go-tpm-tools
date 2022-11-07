package main

import (
	"fmt"
	"os"
)

const attestationToken = "/run/container_launcher/attestation_verifier_claims_token"

func main() {
	fmt.Println("printer container ran with: ", os.Args)
	env := os.Environ()
	fmt.Println("env:", env)

	_, err := os.Stat(attestationToken)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("token exists!")
}
