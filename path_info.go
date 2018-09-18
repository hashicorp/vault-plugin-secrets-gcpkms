package gcpkms

import (
	"context"

	"github.com/hashicorp/vault-plugin-secrets-gcpkms/version"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) pathInfo() *framework.Path {
	return &framework.Path{
		Pattern: "info",

		HelpSynopsis: "Display information about this plugin",
		HelpDescription: `
Displays information about the plugin, such as the plugin version, where to
file issues, and how to get help.
`,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: withFieldValidator(b.pathInfoRead),
		},
	}
}

// pathInfoRead corresponds to READ gcpkms/info and is used to display information
// about the plugin.
func (b *backend) pathInfoRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"name":    version.Name,
			"commit":  version.GitCommit,
			"version": version.Version,
		},
	}, nil
}
