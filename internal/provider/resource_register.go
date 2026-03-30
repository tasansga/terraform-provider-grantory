package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRegister() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"host_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Host identifier that owns the register entry.",
				ForceNew:    true,
			},
			"unique_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Optional unique key used to enforce register uniqueness within a namespace.",
			},
			"schema_definition_id": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Optional schema definition identifier used to validate register payloads.",
			},
			"payload": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "JSON-encoded payload that describes the registered item.",
				DiffSuppressFunc: payloadDiffSuppress,
			},
			"mutable": {
				Type:        schema.TypeBool,
				Optional:    true,
				ForceNew:    true,
				Description: "Whether register payload updates are allowed in place.",
			},
			"labels": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Optional labels that tag the register entry.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
		CreateContext: resourceRegisterCreate,
		ReadContext:   resourceRegisterRead,
		UpdateContext: resourceRegisterUpdate,
		DeleteContext: resourceRegisterDelete,
		CustomizeDiff: customdiff.ForceNewIf("payload", func(_ context.Context, d *schema.ResourceDiff, _ any) bool {
			return payloadChangeRequiresReplacement(d)
		}),
	}
}

func resourceRegisterCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)

	var registerPayload map[string]any
	if raw, ok := d.GetOk("payload"); ok {
		if payloadString, _ := raw.(string); payloadString != "" {
			parsed, err := parseJSONString(payloadString)
			if err != nil {
				return diag.Diagnostics{{
					Severity: diag.Error,
					Summary:  "invalid register payload",
					Detail:   err.Error(),
				}}
			}
			registerPayload = parsed
		}
	}

	payload := apiRegisterCreatePayload{
		HostID:             d.Get("host_id").(string),
		SchemaDefinitionID: d.Get("schema_definition_id").(string),
		UniqueKey:          d.Get("unique_key").(string),
		Payload:            registerPayload,
		Mutable:            d.Get("mutable").(bool),
		Labels:             expandStringMap(extractMap(d.Get("labels"))),
	}

	created, err := client.CreateRegister(ctx, payload)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(created.ID)
	return resourceRegisterRefresh(ctx, d, created)
}

func resourceRegisterRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	registerID := d.Id()
	if registerID == "" {
		return nil
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
	return resourceRegisterRefresh(ctx, d, reg)
}

func resourceRegisterUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	var payload apiRegisterUpdatePayload
	changed := false
	if d.HasChange("payload") {
		parsed, err := parseJSONPatchPayload(d.Get("payload").(string))
		if err != nil {
			return diag.Diagnostics{{
				Severity: diag.Error,
				Summary:  "invalid register payload",
				Detail:   err.Error(),
			}}
		}
		payload.Payload = parsed
		changed = true
	}
	if d.HasChange("labels") {
		payload.Labels = expandStringMap(extractMap(d.Get("labels")))
		changed = true
	}
	if !changed {
		return nil
	}

	updated, err := client.UpdateRegister(ctx, d.Id(), payload)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(updated.ID)
	return resourceRegisterRefresh(ctx, d, updated)
}

func resourceRegisterDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)
	if err := client.DeleteRegister(ctx, d.Id()); err != nil {
		if isNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	d.SetId("")
	return nil
}

func resourceRegisterRefresh(ctx context.Context, d *schema.ResourceData, reg apiRegister) diag.Diagnostics {
	return setRegisterAttributes(d, reg)
}

func setRegisterAttributes(d *schema.ResourceData, reg apiRegister) diag.Diagnostics {
	var diags diag.Diagnostics

	if err := d.Set("host_id", reg.HostID); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("unique_key", reg.UniqueKey); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("schema_definition_id", reg.SchemaDefinitionID); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if reg.Payload != nil {
		if additional := setJSONStringAttribute(d, "payload", reg.Payload); additional != nil {
			diags = append(diags, additional...)
		}
	}
	if err := d.Set("mutable", reg.Mutable); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if reg.Labels != nil {
		if err := d.Set("labels", flattenStringMap(reg.Labels)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}

	return diags
}
