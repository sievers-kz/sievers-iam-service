package main

import (
	"fmt"
	"log"

	"github.com/sievers-kz/sievers-iam-service/internal/configuration"
)

func main() {
	config, err := configuration.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	fmt.Printf("%+v\n", config)
}
