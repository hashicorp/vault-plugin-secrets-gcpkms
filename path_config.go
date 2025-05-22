// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/helper/pluginidentityutil"
	"github.com/hashicorp/vault/sdk/helper/pluginutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfig defines the gcpkms/config base path on the backend.
func (b *backend) pathConfig() *framework.Path {

	p := &framework.Path{
		Pattern: "config",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixGoogleCloudKMS,
		},

		HelpSynopsis: "Configure the GCP KMS secrets engine",
		HelpDescription: "Configure the GCP KMS secrets engine with credentials " +
			"or manage the requested scope(s).",

		Fields: map[string]*framework.FieldSchema{
			"credentials": {
				Type: framework.TypeString,
				Description: `
The credentials to use for authenticating to Google Cloud. Leave this blank to
use the Default Application Credentials or instance metadata authentication.
`,
			},

			"scopes": {
				Type: framework.TypeCommaStringSlice,
				Description: `
The list of full-URL scopes to request when authenticating. By default, this
requests https://www.googleapis.com/auth/cloudkms.
`,
			},
			"service_account_email": {
				Type:        framework.TypeString,
				Description: `Email ID for the Service Account to impersonate for Workload Identity Federation.`,
			},
		},

		ExistenceCheck: b.pathConfigExists,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathConfigWrite),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "configure",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathConfigWrite),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "configure",
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathConfigRead),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "read",
					OperationSuffix: "configuration",
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: withFieldValidator(b.pathConfigDelete),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "delete",
					OperationSuffix: "configuration",
				},
			},
		},
	}
	pluginidentityutil.AddPluginIdentityTokenFields(p.Fields)
	automatedrotationutil.AddAutomatedRotationFields(p.Fields)
	return p
}

// pathConfigExists checks if the configuration exists.
func (b *backend) pathConfigExists(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return false, errwrap.Wrapf("failed to get configuration from storage: {{err}}", err)
	}
	if entry == nil || len(entry.Value) == 0 {
		return false, nil
	}
	return true, nil
}

// pathConfigRead corresponds to READ gcpkms/config and is used to
// read the current configuration.
func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	c, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	configData := map[string]interface{}{
		"scopes":                c.Scopes,
		"service_account_email": c.ServiceAccountEmail,
	}

	c.PopulatePluginIdentityTokenData(configData)
	c.PopulateAutomatedRotationData(configData)

	return &logical.Response{
		Data: configData,
	}, nil
}

// pathConfigWrite corresponds to both CREATE and UPDATE gcpkms/config and is
// used to create or update the current configuration.
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the current configuration, if it exists
	c, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	credentialsRaw, setNewCreds := d.GetOk("credentials")
	if setNewCreds {
		// If the credentials are set, we need to parse them if they are not empty in the case we switch back to Workload Identity
		if len(strings.TrimSpace(credentialsRaw.(string))) > 0 {
			_, err := gcputil.Credentials(credentialsRaw.(string))
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("invalid credentials JSON file: %v", err)), nil
			}
		}
		c.Credentials = strings.TrimSpace(credentialsRaw.(string))
	}

	if v, ok := d.GetOk("scopes"); ok {
		nv := strutil.RemoveDuplicates(v.([]string), true)
		if !strutil.EquivalentSlices(nv, c.Scopes) {
			c.Scopes = nv
			setNewCreds = true
		}
	}

	// set plugin identity token fields
	if err := c.ParsePluginIdentityTokenFields(d); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// set automated root rotation fields
	if err := c.ParseAutomatedRotationFields(d); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// set Service Account email
	saEmail, ok := d.GetOk("service_account_email")
	if ok {
		c.ServiceAccountEmail = saEmail.(string)
		setNewCreds = true
	}

	if c.IdentityTokenAudience != "" && c.Credentials != "" {
		return logical.ErrorResponse("only one of 'credentials' or 'identity_token_audience' can be set"), nil
	}

	if c.IdentityTokenAudience != "" && c.ServiceAccountEmail == "" {
		return logical.ErrorResponse("missing required 'service_account_email' when 'identity_token_audience' is set"), nil
	}

	// generate token to check if WIF is enabled on this edition of Vault
	if c.IdentityTokenAudience != "" {
		_, err := b.System().GenerateIdentityToken(ctx, &pluginutil.IdentityTokenRequest{
			Audience: c.IdentityTokenAudience,
		})
		if err != nil {
			if errors.Is(err, pluginidentityutil.ErrPluginWorkloadIdentityUnsupported) {
				return logical.ErrorResponse(err.Error()), nil
			}
			return nil, err
		}
	}

	// if token audience or TTL is being updated, ensure cached credentials are cleared
	_, audOk := d.GetOk("identity_token_audience")
	_, ttlOk := d.GetOk("identity_token_ttl")
	if audOk || ttlOk {
		setNewCreds = true
	}
	// Only do the following if the config is different
	if setNewCreds {
		// Generate a new storage entry
		entry, err := logical.StorageEntryJSON("config", c)
		if err != nil {
			return nil, err
		}

		// Save the storage entry
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("failed to persist configuration to storage: %s", err)
		}

		// Invalidate existing client so it reads the new configuration
		b.ResetClient()
	}

	return nil, nil
}

// pathConfigDelete corresponds to DELETE gcpkms/config and is used to delete
// all the configuration.
func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "config"); err != nil {
		return nil, errwrap.Wrapf("failed to delete from storage: {{err}}", err)
	}

	// Invalidate existing client so it reads the new configuration
	b.ResetClient()

	return nil, nil
}
