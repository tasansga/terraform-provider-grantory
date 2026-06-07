package provider

import (
	"context"
	"encoding/hex"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
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
			"key_format": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "hex",
				ForceNew:     true,
				Description:  "Format of the public and private keys provided as input. Use \"pem\" for PKCS#8 (private) and SPKI (public) PEM formats.",
				ValidateFunc: validation.StringInSlice([]string{"hex", "pem"}, false),
			},
			"public_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Optional Ed25519 public key in hex or PEM format for signing requests.",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					format := d.Get("key_format").(string)
					oldBytes, _ := decodeKey(old, format, false)
					newBytes, _ := decodeKey(new, format, false)

					// Fallback to hex for server-side values or vice versa
					if oldBytes == nil {
						oldBytes, _ = decodeKey(old, "hex", false)
					}
					if newBytes == nil {
						newBytes, _ = decodeKey(new, "hex", false)
					}

					if oldBytes == nil || newBytes == nil {
						return old == new
					}
					return string(oldBytes) == string(newBytes)
				},
			},
			"labels": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Optional labels that accompany the host registration.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"ed25519_private_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "Optional Ed25519 private key in hex or PEM format for signing requests. Required if the host has a public key registered. Consider using ed25519_private_key_file or ed25519_private_key_env for better security.",
			},
			"ed25519_private_key_file": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Optional path to a file containing the hex or PEM-encoded Ed25519 private key.",
			},
			"ed25519_private_key_env": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Optional environment variable name containing the hex or PEM-encoded Ed25519 private key.",
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

	format := d.Get("key_format").(string)
	publicKeyInput := d.Get("public_key").(string)

	var publicKeyHex string
	if publicKeyInput != "" {
		pubBytes, err := decodeKey(publicKeyInput, format, false)
		if err != nil {
			return diag.FromErr(err)
		}
		publicKeyHex = hex.EncodeToString(pubBytes)
	}

	payload := apiHostCreatePayload{
		UniqueKey: d.Get("unique_key").(string),
		PublicKey: publicKeyHex,
		Labels:    expandStringMap(rawLabels),
	}

	host, err := client.CreateHost(ctx, payload)
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

	host, err := client.GetHost(ctx, hostID)
	if err != nil {
		if isNotFound(err) {
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

	ctx, err := contextWithPrivateKey(ctx, d)
	if err != nil {
		return diag.FromErr(err)
	}

	labels := expandStringMap(extractMap(d.Get("labels")))
	updated, err := client.UpdateHostLabels(ctx, d.Id(), labels)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(updated.ID)
	return resourceHostRefresh(ctx, d, updated)
}

func resourceHostDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	client := meta.(*grantoryClient)

	ctx, err := contextWithPrivateKey(ctx, d)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := client.DeleteHost(ctx, d.Id()); err != nil {
		if isNotFound(err) {
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

	newPublicKey := host.PublicKey
	if oldPublicKey, ok := d.Get("public_key").(string); ok && oldPublicKey != "" {
		format := d.Get("key_format").(string)
		oldBytes, _ := decodeKey(oldPublicKey, format, false)
		newBytes, _ := decodeKey(host.PublicKey, "hex", false)
		if oldBytes != nil && newBytes != nil && string(oldBytes) == string(newBytes) {
			newPublicKey = oldPublicKey
		}
	}

	if err := d.Set("public_key", newPublicKey); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if host.Labels != nil {
		if err := d.Set("labels", flattenStringMap(host.Labels)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	return diags
}
