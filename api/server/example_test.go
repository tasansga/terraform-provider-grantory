package server_test

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/tasansga/terraform-provider-grantory/api/server"
)

func ExampleDefaultConfig() {
	cfg := server.DefaultConfig()
	dataDir, err := os.MkdirTemp("", "grantory-api-server-example-*")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(dataDir)
	}()
	cfg.Database = dataDir
	cfg.BindAddr = "127.0.0.1:0"
	cfg.TLSBind = "off"

	srv, err := server.New(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = srv.Close()
	}()

	fmt.Println(cfg.BindAddr != "")
	// Output: true
}
