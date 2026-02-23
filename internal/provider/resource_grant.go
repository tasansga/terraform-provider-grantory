package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGrant() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"request_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Request identifier that owns this grant.",
				ForceNew:    true,
			},
			"payload": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "JSON-encoded payload delivered by the grant when a request is approved.",
			},
		},
		CreateContext: resourceGrantCreate,
		ReadContext:   resourceGrantRead,
		DeleteContext: resourceGrantDelete,
	}
}

func resourceGrantCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)

	var grantPayload map[string]any
	if raw, ok := d.GetOk("payload"); ok {
		if payloadString, _ := raw.(string); payloadString != "" {
			parsed, err := parseJSONString(payloadString)
			if err != nil {
				return diag.Diagnostics{{
					Severity: diag.Error,
					Summary:  "invalid grant payload",
					Detail:   err.Error(),
				}}
			}
			grantPayload = parsed
		}
	}

	created, err := client.createGrant(ctx, apiGrantCreatePayload{
		RequestID: d.Get("request_id").(string),
		Payload:   grantPayload,
	})
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(created.ID)
	return resourceGrantRefresh(ctx, d, created)
}

func resourceGrantRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	grantID := d.Id()
	if grantID == "" {
		return nil
	}

	grant, err := client.getGrant(ctx, grantID)
	if err != nil {
		if errors.Is(err, errResourceNotFound) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId(grant.ID)
	return resourceGrantRefresh(ctx, d, grant)
}

func resourceGrantDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	if err := client.deleteGrant(ctx, d.Id()); err != nil {
		if errors.Is(err, errResourceNotFound) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId("")
	return nil
}

func resourceGrantRefresh(ctx context.Context, d *schema.ResourceData, grant apiGrant) diag.Diagnostics {
	var diags diag.Diagnostics
	if err := d.Set("request_id", grant.RequestID); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if additional := setJSONStringAttribute(d, "payload", grant.Payload); additional != nil {
		diags = append(diags, additional...)
	}
	return diags
}
