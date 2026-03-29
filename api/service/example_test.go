package service_test

import (
	"context"
	"fmt"
	"log"

	"github.com/tasansga/terraform-provider-grantory/api/service"
)

func ExampleNewStoreFromDatabase() {
	store, err := service.NewStoreFromDatabase(context.Background(), ":memory:")
	if err != nil {
		log.Fatal(err)
	}

	svc := service.New(store)
	host, err := svc.CreateHost(context.Background(), service.HostCreatePayload{
		UniqueKey: "app-01",
		Labels:    map[string]string{"env": "dev"},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(host.UniqueKey)
	// Output: app-01
}
