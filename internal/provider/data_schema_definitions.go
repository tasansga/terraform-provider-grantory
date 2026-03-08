package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSchemaDefinitions() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"schema_definitions": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Schema definitions returned by Grantory.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"schema_definition_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"request_schema": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"grant_schema": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
		ReadContext: dataSchemaDefinitionsRead,
	}
}

func dataSchemaDefinitionsRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	defs, err := client.listSchemaDefinitions(ctx)
	if err != nil {
		return diag.FromErr(err)
	}

	values := make([]map[string]any, 0, len(defs))
	hashEntries := make([]schemaDefinitionListEntry, 0, len(defs))
	for _, def := range defs {
		entry := map[string]any{
			"schema_definition_id": def.ID,
			"request_schema":       string(def.RequestSchema),
			"grant_schema":         string(def.GrantSchema),
		}
		values = append(values, entry)
		hashEntries = append(hashEntries, schemaDefinitionListEntry{
			SchemaDefinitionID: def.ID,
			RequestSchema:      string(def.RequestSchema),
			GrantSchema:        string(def.GrantSchema),
		})
	}

	if err := d.Set("schema_definitions", values); err != nil {
		return diag.FromErr(err)
	}
	id, err := hashAsJSON(map[string]any{
		"schema_definitions": hashEntries,
	})
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)
	return nil
}

type schemaDefinitionListEntry struct {
	SchemaDefinitionID string `json:"schema_definition_id"`
	RequestSchema      string `json:"request_schema"`
	GrantSchema        string `json:"grant_schema"`
}
