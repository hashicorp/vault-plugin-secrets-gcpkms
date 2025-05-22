// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestBackend_PathConfigRead(t *testing.T) {

	t.Run("field_validation", func(t *testing.T) {

		testFieldValidation(t, logical.ReadOperation, "config")
	})

	t.Run("not_exist", func(t *testing.T) {

		b, storage := testBackend(t)
		ctx := context.Background()
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      "config",
		})
		if err != nil {
			t.Fatal(err)
		}

		if _, ok := resp.Data["scopes"]; !ok {
			t.Errorf("expected %q to include %q", resp.Data, "scopes")
		}
	})

	t.Run("exist", func(t *testing.T) {

		b, storage := testBackend(t)

		entry, err := logical.StorageEntryJSON("config", &Config{
			Scopes:      []string{"foo"},
			Credentials: "creds",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Put(context.Background(), entry); err != nil {
			t.Fatal(err)
		}

		ctx := context.Background()
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      "config",
		})
		if err != nil {
			t.Fatal(err)
		}

		if v, exp := resp.Data["scopes"].([]string), []string{"foo"}; !reflect.DeepEqual(v, exp) {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if _, ok := resp.Data["credentials"]; ok {
			t.Errorf("should not return credentials")
		}
	})
}

func TestBackend_PathConfigUpdate(t *testing.T) {

	t.Run("field_validation", func(t *testing.T) {

		testFieldValidation(t, logical.UpdateOperation, "config")
	})

	t.Run("not_exist", func(t *testing.T) {
		credBytes, err := getTestCredentials()
		credJson := string(credBytes)
		b, storage := testBackend(t)
		if _, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "config",
			Data: map[string]interface{}{
				"scopes":      "foo,bar",
				"credentials": credJson,
			},
		}); err != nil {
			t.Fatal(err)
		}

		config, err := b.Config(context.Background(), storage)
		if err != nil {
			t.Fatal(err)
		}

		if v, exp := config.Credentials, strings.TrimSpace(credJson); v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := config.Scopes, []string{"bar", "foo"}; !reflect.DeepEqual(v, exp) {
			t.Errorf("expected %q to be %q", v, exp)
		}
	})

	t.Run("exist", func(t *testing.T) {

		b, storage := testBackend(t)
		credBytes, err := getTestCredentials()
		credJson := string(credBytes)
		entry, err := logical.StorageEntryJSON("config", &Config{
			Scopes:      []string{"foo"},
			Credentials: strings.TrimSpace(credJson),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Put(context.Background(), entry); err != nil {
			t.Fatal(err)
		}

		if _, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "config",
			Data: map[string]interface{}{
				"scopes":      "foo,bar",
				"credentials": credJson,
			},
		}); err != nil {
			t.Fatal(err)
		}

		config, err := b.Config(context.Background(), storage)
		if err != nil {
			t.Fatal(err)
		}

		if v, exp := config.Credentials, strings.TrimSpace(credJson); v != exp {
			t.Errorf("expected %q to be %q", v, exp)
		}

		if v, exp := config.Scopes, []string{"bar", "foo"}; !reflect.DeepEqual(v, exp) {
			t.Errorf("expected %q to be %q", v, exp)
		}
	})
}

func TestBackend_PathConfigDelete(t *testing.T) {

	t.Run("field_validation", func(t *testing.T) {

		testFieldValidation(t, logical.DeleteOperation, "config")
	})

	t.Run("not_exist", func(t *testing.T) {

		b, storage := testBackend(t)
		if _, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.DeleteOperation,
			Path:      "config",
		}); err != nil {
			t.Fatal(err)
		}

		config, err := b.Config(context.Background(), storage)
		if err != nil {
			t.Fatal(err)
		}

		if def := DefaultConfig(); !reflect.DeepEqual(config, def) {
			t.Errorf("expected %v to be %v", config, def)
		}
	})

	t.Run("exist", func(t *testing.T) {

		b, storage := testBackend(t)

		entry, err := logical.StorageEntryJSON("config", &Config{
			Scopes:      []string{"foo"},
			Credentials: "creds",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Put(context.Background(), entry); err != nil {
			t.Fatal(err)
		}

		if _, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.DeleteOperation,
			Path:      "config",
		}); err != nil {
			t.Fatal(err)
		}

		config, err := b.Config(context.Background(), storage)
		if err != nil {
			t.Fatal(err)
		}

		if def := DefaultConfig(); !reflect.DeepEqual(config, def) {
			t.Errorf("expected %v to be %v", config, def)
		}
	})
}

func getTestCredentials() ([]byte, error) {
	creds := map[string]interface{}{
		"client_email":   "testUser@google.com",
		"client_id":      "user123",
		"private_key_id": "privateKey123",
		"private_key":    "iAmAPrivateKey",
		"project_id":     "project123",
	}

	credJson, err := jsonutil.EncodeJSON(creds)
	if err != nil {
		return nil, err
	}

	return credJson, nil
}
