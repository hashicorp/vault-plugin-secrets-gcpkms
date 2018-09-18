package gcpkms

import (
	"context"
	"testing"

	"github.com/hashicorp/vault-plugin-secrets-gcpkms/version"
	"github.com/hashicorp/vault/logical"
)

func TestBackend_PathInfoRead(t *testing.T) {
	t.Parallel()

	t.Run("field_validation", func(t *testing.T) {
		t.Parallel()
		testFieldValidation(t, logical.ReadOperation, "info")
	})

	t.Run("info", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)
		ctx := context.Background()
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      "info",
		})
		if err != nil {
			t.Fatal(err)
		}

		if v, exp := resp.Data["version"].(string), version.Version; v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}
	})
}
