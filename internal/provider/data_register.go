package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataRegister() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"register_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Identifier of the register entry to fetch.",
			},
			"host_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Host identifier that owns the register entry.",
			},
			"unique_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Unique key used to enforce register uniqueness within a namespace.",
			},
			"schema_definition_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Schema definition identifier associated with the register.",
			},
			"payload": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "JSON-encoded payload that describes the registered item.",
			},
			"labels": {
				Type:        schema.TypeMap,
				Computed:    true,
				Optional:    true,
				Description: "Labels associated with the register entry.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
		ReadContext: dataRegisterRead,
	}
}

func dataRegisterRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	registerID := d.Get("register_id").(string)
	if registerID == "" {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  "register_id is required",
		}}
	}

	reg, err := client.GetRegister(ctx, registerID)
	if err != nil {
		if isNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId(reg.ID)
	return setRegisterAttributes(d, reg)
}
