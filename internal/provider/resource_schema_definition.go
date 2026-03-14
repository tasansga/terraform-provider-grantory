package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSchemaDefinition() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"unique_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Optional unique key used to enforce schema definition uniqueness within a namespace.",
			},
			"schema": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "JSON Schema definition payload.",
			},
			"labels": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Optional labels that tag the schema definition.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
		CreateContext: resourceSchemaDefinitionCreate,
		ReadContext:   resourceSchemaDefinitionRead,
		UpdateContext: resourceSchemaDefinitionUpdate,
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

	created, err := client.CreateSchemaDefinition(ctx, apiSchemaDefinitionCreatePayload{
		UniqueKey: d.Get("unique_key").(string),
		Schema:    schemaValue,
		Labels:    expandStringMap(extractMap(d.Get("labels"))),
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

	def, err := client.GetSchemaDefinition(ctx, defID)
	if err != nil {
		if isNotFound(err) {
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

	if err := client.DeleteSchemaDefinition(ctx, defID); err != nil {
		if isNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId("")
	return nil
}

func resourceSchemaDefinitionUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	if !d.HasChange("labels") {
		return nil
	}

	updated, err := client.UpdateSchemaDefinitionLabels(ctx, d.Id(), expandStringMap(extractMap(d.Get("labels"))))
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(updated.ID)
	return resourceSchemaDefinitionRefresh(d, updated)
}

func resourceSchemaDefinitionRefresh(d *schema.ResourceData, def apiSchemaDefinition) diag.Diagnostics {
	var diags diag.Diagnostics
	if err := d.Set("unique_key", def.UniqueKey); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("schema", string(def.Schema)); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("labels", flattenStringMap(def.Labels)); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	return diags
}
