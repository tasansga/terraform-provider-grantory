package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataGrants() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"grants": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Grants stored in Grantory, one entry per ID.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"grant_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"request_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
		ReadContext: dataGrantsRead,
	}
}

func dataGrantsRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)

	grants, err := client.ListGrants(ctx)
	if err != nil {
		return diag.FromErr(err)
	}

	values := make([]map[string]any, 0, len(grants))
	hashEntries := make([]grantListEntry, 0, len(grants))
	for _, grant := range grants {
		entry := map[string]any{
			"grant_id":   grant.ID,
			"request_id": grant.RequestID,
		}
		values = append(values, entry)
		hashEntries = append(hashEntries, grantListEntry{
			GrantID:   grant.ID,
			RequestID: grant.RequestID,
		})
	}

	if err := d.Set("grants", values); err != nil {
		return diag.FromErr(err)
	}
	id, err := hashAsJSON(hashEntries)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)
	return nil
}

type grantListEntry struct {
	GrantID   string `json:"grant_id"`
	RequestID string `json:"request_id"`
}
