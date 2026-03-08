package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSchemaDefinition() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"schema": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "JSON Schema definition payload.",
			},
		},
		CreateContext: resourceSchemaDefinitionCreate,
		ReadContext:   resourceSchemaDefinitionRead,
		DeleteContext: resourceSchemaDefinitionDelete,
	}
}

func resourceSchemaDefinitionCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)

	schemaValue, err := parseRawJSON(d.Get("schema").(string))
	if err != nil {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  "invalid schema",
			Detail:   err.Error(),
		}}
	}
	if len(schemaValue) == 0 {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  "schema is required",
		}}
	}

	created, err := client.createSchemaDefinition(ctx, apiSchemaDefinition{
		Schema: schemaValue,
	})
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(created.ID)
	return resourceSchemaDefinitionRefresh(d, created)
}

func resourceSchemaDefinitionRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	defID := d.Id()
	if defID == "" {
		return nil
	}

	def, err := client.getSchemaDefinition(ctx, defID)
	if err != nil {
		if errors.Is(err, errResourceNotFound) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId(def.ID)
	return resourceSchemaDefinitionRefresh(d, def)
}

func resourceSchemaDefinitionDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	defID := d.Id()
	if defID == "" {
		return nil
	}

	if err := client.deleteSchemaDefinition(ctx, defID); err != nil {
		if errors.Is(err, errResourceNotFound) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId("")
	return nil
}

func resourceSchemaDefinitionRefresh(d *schema.ResourceData, def apiSchemaDefinition) diag.Diagnostics {
	if err := d.Set("schema", string(def.Schema)); err != nil {
		return diag.FromErr(err)
	}
	return nil
}
