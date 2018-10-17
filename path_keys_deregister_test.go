package gcpkms

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestPathKeysDeregister_Write(t *testing.T) {
	t.Parallel()

	t.Run("field_validation", func(t *testing.T) {
		t.Parallel()
		testFieldValidation(t, logical.CreateOperation, "keys/deregister/my-key")
		testFieldValidation(t, logical.UpdateOperation, "keys/deregister/my-key")
	})

	cases := []struct {
		name string
		c    []byte
		err  bool
	}{
		{
			"key_exists",
			[]byte(`{"name":"my-key", "crypto_key_id":"foo"}`),
			false,
		},
		{
			"key_not_exists",
			nil,
			true,
		},
	}

	t.Run("group", func(t *testing.T) {
		for _, tc := range cases {
			tc := tc

			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				b, storage := testBackend(t)

				if tc.c != nil {
					if err := storage.Put(context.Background(), &logical.StorageEntry{
						Key:   "keys/my-key",
						Value: tc.c,
					}); err != nil {
						t.Fatal(err)
					}
				}

				_, err := b.HandleRequest(context.Background(), &logical.Request{
					Storage:   storage,
					Operation: logical.UpdateOperation,
					Path:      "keys/deregister/my-key",
				})
				if err != nil {
					if tc.err {
						return
					}

					t.Fatal(err)
				}

				ctx := context.Background()
				if _, err := b.Key(ctx, storage, "my-key"); err != ErrKeyNotFound {
					t.Fatal(err)
				}
			})
		}
	})
}
