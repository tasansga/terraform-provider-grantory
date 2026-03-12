package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataGrant() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"grant_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Identifier of the grant to fetch.",
			},
			"request_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Identifier of the request that owns the grant.",
			},
			"payload": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON-encoded payload delivered by the grant, if any.",
			},
		},
		ReadContext: dataGrantRead,
	}
}

func dataGrantRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	grantID := d.Get("grant_id").(string)

	var diags diag.Diagnostics

	grant, err := client.GetGrant(ctx, grantID)
	if err != nil {
		if isNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	if err := d.Set("grant_id", grant.ID); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("request_id", grant.RequestID); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}

	if grant.Payload != nil {
		if additional := setJSONStringAttribute(d, "payload", grant.Payload); additional != nil {
			diags = append(diags, additional...)
		}
	}

	d.SetId(grant.ID)
	return diags
}
