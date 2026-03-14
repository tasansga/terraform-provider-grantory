package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSchemaDefinition() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"schema_definition_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Identifier of the schema definition to fetch.",
			},
			"unique_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Unique key used to enforce schema definition uniqueness within a namespace.",
			},
			"schema": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON Schema definition payload.",
			},
			"labels": {
				Type:        schema.TypeMap,
				Computed:    true,
				Optional:    true,
				Description: "Labels attached to the schema definition.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
		ReadContext: dataSchemaDefinitionRead,
	}
}

func dataSchemaDefinitionRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	defID := d.Get("schema_definition_id").(string)
	if defID == "" {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  "schema_definition_id is required",
		}}
	}

	def, err := client.GetSchemaDefinition(ctx, defID)
	if err != nil {
		if isNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId(def.ID)
	if err := d.Set("unique_key", def.UniqueKey); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("schema", string(def.Schema)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("labels", flattenStringMap(def.Labels)); err != nil {
		return diag.FromErr(err)
	}
	return nil
}
