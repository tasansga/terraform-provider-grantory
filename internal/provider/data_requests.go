package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataRequests() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"has_grant": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether returned requests must already have a grant.",
			},
			"labels": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Labels that each returned request must include.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"host_labels": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Labels that each returned request's host must include.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"requests": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Requests returned by Grantory.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"request_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"host_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"has_grant": {
							Type:     schema.TypeBool,
							Computed: true,
						},
					},
				},
			},
		},
		ReadContext: dataRequestsRead,
	}
}

func dataRequestsRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	opts := requestListOptions{
		Labels:     expandStringMap(extractMap(d.Get("labels"))),
		HostLabels: expandStringMap(extractMap(d.Get("host_labels"))),
	}
	if raw, ok := d.GetOk("has_grant"); ok {
		value := raw.(bool)
		opts.HasGrant = &value
	}

	requests, err := client.listRequests(ctx, opts)
	if err != nil {
		return diag.FromErr(err)
	}

	values := make([]map[string]any, 0, len(requests))
	hashEntries := make([]requestListEntry, 0, len(requests))
	for _, req := range requests {
		entry := map[string]any{
			"request_id": req.ID,
			"host_id":    req.HostID,
			"has_grant":  req.HasGrant,
		}
		values = append(values, entry)
		hashEntries = append(hashEntries, requestListEntry{
			RequestID: req.ID,
			HostID:    req.HostID,
			HasGrant:  req.HasGrant,
		})
	}

	if err := d.Set("requests", values); err != nil {
		return diag.FromErr(err)
	}
	id, err := hashAsJSON(map[string]any{
		"labels":      opts.Labels,
		"host_labels": opts.HostLabels,
		"requests":    hashEntries,
	})
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)
	return nil
}

type requestListEntry struct {
	RequestID string `json:"request_id"`
	HostID    string `json:"host_id"`
	HasGrant  bool   `json:"has_grant"`
}
