package provider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSchemaDefinitions() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"labels": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Labels that each returned schema definition must include.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
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
						"unique_key": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"schema": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"labels": {
							Type:     schema.TypeMap,
							Computed: true,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
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
	defs, err := client.ListSchemaDefinitions(ctx)
	if err != nil {
		return diag.FromErr(err)
	}

	labels := expandStringMap(extractMap(d.Get("labels")))
	filtered := defs
	if len(labels) > 0 {
		filtered = make([]apiSchemaDefinition, 0, len(defs))
		for _, def := range defs {
			if matchesLabelFilters(def.Labels, labels) {
				filtered = append(filtered, def)
			}
		}
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].ID < filtered[j].ID
	})

	values := make([]map[string]any, 0, len(filtered))
	hashEntries := make([]schemaDefinitionListEntry, 0, len(filtered))
	for _, def := range filtered {
		entry := map[string]any{
			"schema_definition_id": def.ID,
			"unique_key":           def.UniqueKey,
			"schema":               string(def.Schema),
		}
		if def.Labels != nil {
			entry["labels"] = flattenStringMap(def.Labels)
		}
		values = append(values, entry)
		hashEntries = append(hashEntries, schemaDefinitionListEntry{
			SchemaDefinitionID: def.ID,
			UniqueKey:          def.UniqueKey,
			Schema:             string(def.Schema),
			Labels:             def.Labels,
		})
	}

	if err := d.Set("schema_definitions", values); err != nil {
		return diag.FromErr(err)
	}
	id, err := hashAsJSON(map[string]any{
		"labels":             labels,
		"schema_definitions": hashEntries,
	})
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)
	return nil
}

type schemaDefinitionListEntry struct {
	SchemaDefinitionID string            `json:"schema_definition_id"`
	UniqueKey          string            `json:"unique_key,omitempty"`
	Schema             string            `json:"schema"`
	Labels             map[string]string `json:"labels,omitempty"`
}
