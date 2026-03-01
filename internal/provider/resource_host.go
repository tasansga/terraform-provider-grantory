package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceHost() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"host_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Server-generated identifier for the host.",
			},
			"unique_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Optional unique key used to enforce host uniqueness within a namespace.",
			},
			"labels": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Optional labels that accompany the host registration.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
		CreateContext: resourceHostCreate,
		ReadContext:   resourceHostRead,
		UpdateContext: resourceHostUpdate,
		DeleteContext: resourceHostDelete,
	}
}

func resourceHostCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	var rawLabels map[string]any
	if value, ok := d.Get("labels").(map[string]any); ok {
		rawLabels = value
	}

	payload := apiHost{
		UniqueKey: d.Get("unique_key").(string),
		Labels:    expandStringMap(rawLabels),
	}

	host, err := client.createHost(ctx, payload)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(host.ID)
	return resourceHostRefresh(ctx, d, host)
}

func resourceHostRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	hostID := d.Id()
	if hostID == "" {
		hostID = d.Get("host_id").(string)
	}

	host, err := client.getHost(ctx, hostID)
	if err != nil {
		if errors.Is(err, errResourceNotFound) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId(host.ID)
	return resourceHostRefresh(ctx, d, host)
}

func resourceHostUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	if !d.HasChange("labels") {
		return nil
	}
	labels := expandStringMap(extractMap(d.Get("labels")))
	updated, err := client.updateHostLabels(ctx, d.Id(), labels)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(updated.ID)
	return resourceHostRefresh(ctx, d, updated)
}

func resourceHostDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	if err := client.deleteHost(ctx, d.Id()); err != nil {
		if errors.Is(err, errResourceNotFound) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId("")
	return nil
}

func resourceHostRefresh(ctx context.Context, d *schema.ResourceData, host apiHost) diag.Diagnostics {
	var diags diag.Diagnostics

	if err := d.Set("host_id", host.ID); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("unique_key", host.UniqueKey); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if host.Labels != nil {
		if err := d.Set("labels", flattenStringMap(host.Labels)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	return diags
}
