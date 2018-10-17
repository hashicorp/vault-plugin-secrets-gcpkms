package main

import (
	"fmt"
	"log"
	"os"

	"github.com/hashicorp/vault-plugin-secrets-gcpkms/version"
)

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		log.Fatal("missing argument")
	}

	switch args[0] {
	case "name":
		fmt.Printf("%s", version.Name)
	case "version":
		fmt.Printf("%s", version.Version)
	default:
		log.Fatalf("unknown arg %q", args[0])
	}
}
