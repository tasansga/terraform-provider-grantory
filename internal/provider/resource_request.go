package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRequest() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"host_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Host identifier that owns the request.",
				ForceNew:    true,
			},
			"unique_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Optional unique key used to enforce request uniqueness within a namespace.",
			},
			"payload": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "JSON-encoded payload that describes the requested resource.",
			},
			"labels": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Optional labels that tag the request.",
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
				Description: "Identifier reported by the Grantory server for the applied grant.",
			},
			"grant_payload": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON-encoded payload delivered by the grant, if any.",
			},
		},
		CreateContext: resourceRequestCreate,
		ReadContext:   resourceRequestRead,
		UpdateContext: resourceRequestUpdate,
		DeleteContext: resourceRequestDelete,
	}
}
func resourceRequestCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)

	var requestPayload map[string]any
	if raw, ok := d.GetOk("payload"); ok {
		if payloadString, _ := raw.(string); payloadString != "" {
			parsed, err := parseJSONString(payloadString)
			if err != nil {
				return diag.Diagnostics{{
					Severity: diag.Error,
					Summary:  "invalid request payload",
					Detail:   err.Error(),
				}}
			}
			requestPayload = parsed
		}
	}

	payload := apiRequest{
		HostID:    d.Get("host_id").(string),
		UniqueKey: d.Get("unique_key").(string),
		Payload:   requestPayload,
		Labels:    expandStringMap(extractMap(d.Get("labels"))),
	}

	created, err := client.createRequest(ctx, payload)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(created.ID)
	return resourceRequestRefresh(ctx, d, created)
}

func resourceRequestRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	reqID := d.Id()
	if reqID == "" {
		return nil
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
	return resourceRequestRefresh(ctx, d, req)
}

func resourceRequestUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	var payload apiRequestUpdatePayload
	changed := false
	if d.HasChange("labels") {
		payload.Labels = expandStringMap(extractMap(d.Get("labels")))
		changed = true
	}
	if !changed {
		return nil
	}

	updated, err := client.updateRequest(ctx, d.Id(), payload)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(updated.ID)
	return resourceRequestRefresh(ctx, d, updated)
}

func resourceRequestDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	if err := client.deleteRequest(ctx, d.Id()); err != nil {
		if errors.Is(err, errResourceNotFound) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId("")
	return nil
}

func resourceRequestRefresh(ctx context.Context, d *schema.ResourceData, req apiRequest) diag.Diagnostics {
	return setRequestAttributes(d, req)
}

func setRequestAttributes(d *schema.ResourceData, req apiRequest) diag.Diagnostics {
	var diags diag.Diagnostics

	if err := d.Set("host_id", req.HostID); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("unique_key", req.UniqueKey); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if req.Payload != nil {
		if additional := setJSONStringAttribute(d, "payload", req.Payload); additional != nil {
			diags = append(diags, additional...)
		}
	}
	if req.Labels != nil {
		if err := d.Set("labels", flattenStringMap(req.Labels)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	if err := d.Set("has_grant", req.HasGrant); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	var grantID any
	if req.GrantID != "" {
		grantID = req.GrantID
		if err := d.Set("grant_id", grantID); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	if grantPayload := extractGrantPayload(req); grantPayload != nil {
		if additional := setJSONStringAttribute(d, "grant_payload", grantPayload); additional != nil {
			diags = append(diags, additional...)
		}
	}

	return diags
}

func extractMap(value any) map[string]any {
	if value == nil {
		return nil
	}
	if result, ok := value.(map[string]any); ok {
		return result
	}
	return nil
}

func extractGrantPayload(req apiRequest) map[string]any {
	if req.Grant == nil || req.Grant.Payload == nil {
		return nil
	}
	if payloadEntry, ok := req.Grant.Payload["payload"]; ok {
		if payloadEntry == nil {
			return nil
		}
		if result, ok := payloadEntry.(map[string]any); ok {
			return result
		}
		return nil
	}
	return req.Grant.Payload
}
