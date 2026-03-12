package provider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataHosts() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"labels": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Labels that each returned host must include.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"hosts": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of registered host IDs.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
		ReadContext: dataHostsRead,
	}
}

func dataHostsRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	labels := expandStringMap(extractMap(d.Get("labels")))
	hosts, err := client.ListHosts(ctx)
	if err != nil {
		return diag.FromErr(err)
	}

	filtered := hosts
	if len(labels) > 0 {
		filtered = make([]apiHost, 0, len(hosts))
		for _, host := range hosts {
			if matchesLabelFilters(host.Labels, labels) {
				filtered = append(filtered, host)
			}
		}
	}

	values := make([]string, 0, len(filtered))

	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].ID < filtered[j].ID
	})
	for _, host := range filtered {
		values = append(values, host.ID)
	}

	if err := d.Set("hosts", values); err != nil {
		return diag.FromErr(err)
	}
	id, err := hashAsJSON(map[string]any{
		"labels": labels,
		"hosts":  values,
	})
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)
	return nil
}
