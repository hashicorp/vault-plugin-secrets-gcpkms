package gcpkms

import (
	"context"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// pathConfig defines the gcpkms/config base path on the backend.
func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",

		HelpSynopsis: "Configure the GCP KMS secrets engine",
		HelpDescription: "Configure the GCP KMS secrets engine with credentials " +
			"or manage the requested scope(s).",

		Fields: map[string]*framework.FieldSchema{
			"credentials": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
The credentials to use for authenticating to Google Cloud. Leave this blank to
use the Default Application Credentials or instance metadata authentication.
`,
			},

			"scopes": &framework.FieldSchema{
				Type: framework.TypeCommaStringSlice,
				Description: `
The list of full-URL scopes to request when authenticating. By default, this
requests https://www.googleapis.com/auth/cloudkms.
`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: withFieldValidator(b.pathConfigUpdate),
			logical.UpdateOperation: withFieldValidator(b.pathConfigUpdate),
			logical.ReadOperation:   withFieldValidator(b.pathConfigRead),
			logical.DeleteOperation: withFieldValidator(b.pathConfigDelete),
		},

		ExistenceCheck: b.pathConfigExistenceCheck,
	}
}

// pathConfigExistenceCheck is used by Vault to determine if a configuration
// already exists. This is used for ACL purposes.
func (b *backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	if c, err := b.Config(ctx, req.Storage); err != nil || c == nil {
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
	if c == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"scopes": c.Scopes,
		},
	}, nil
}

// pathConfigUpdate corresponds to both CREATE and UPDATE gcpkms/config and is
// used to create or update the current configuration.
func (b *backend) pathConfigUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the current configuration, if it exists
	c, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Update the configuration
	changed, err := c.Update(d)
	if err != nil {
		return nil, logical.CodedError(422, err.Error())
	}

	// Only do the following if the config is different
	if changed {
		// Generate a new storage entry
		entry, err := logical.StorageEntryJSON("config", c)
		if err != nil {
			return nil, errwrap.Wrapf("failed to generate JSON configuration: {{err}}", err)
		}

		// Save the storage entry
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, errwrap.Wrapf("failed to persist configuration to storage: {{err}}", err)
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
