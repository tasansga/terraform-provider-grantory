package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataHost() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"host_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Identifier of the host to fetch.",
			},
			"unique_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Unique key used to enforce host uniqueness within a namespace.",
			},
			"labels": {
				Type:        schema.TypeMap,
				Computed:    true,
				Optional:    true,
				Description: "Labels attached to the host.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
		ReadContext: dataHostRead,
	}
}

func dataHostRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	hostID := d.Get("host_id").(string)
	if hostID == "" {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  "host_id is required",
		}}
	}

	host, err := client.GetHost(ctx, hostID)
	if err != nil {
		if isNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId(host.ID)
	if err := d.Set("host_id", host.ID); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("unique_key", host.UniqueKey); err != nil {
		return diag.FromErr(err)
	}
	if host.Labels != nil {
		if err := d.Set("labels", flattenStringMap(host.Labels)); err != nil {
			return diag.FromErr(err)
		}
	}
	return nil
}
