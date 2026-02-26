package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataRequest() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"request_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Identifier of the request to fetch.",
			},
			"host_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Host identifier that owns the returned request.",
			},
			"unique_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Unique key used to enforce request uniqueness within a namespace.",
			},
			"payload": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "JSON-encoded payload that describes the requested resource.",
			},
			"labels": {
				Type:        schema.TypeMap,
				Computed:    true,
				Optional:    true,
				Description: "Labels attached to the request.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"has_grant": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates whether the server has created a matching grant.",
			},
			"grant_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "Identifier reported by the Grantory server for the applied grant.",
			},
			"grant_payload": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "JSON-encoded payload delivered by the grant, if any.",
			},
		},
		ReadContext: dataRequestRead,
	}
}

func dataRequestRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	reqID := d.Get("request_id").(string)
	if reqID == "" {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  "request_id is required",
		}}
	}

	req, err := client.getRequest(ctx, reqID)
	if err != nil {
		if errors.Is(err, errResourceNotFound) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId(req.ID)
	return setRequestAttributes(d, req)
}
