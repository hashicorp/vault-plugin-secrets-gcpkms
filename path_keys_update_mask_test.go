// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package gcpkms

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	kmsapi "cloud.google.com/go/kms/apiv1"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"
)

type fakeKMS struct {
	kmspb.UnimplementedKeyManagementServiceServer
	mu      sync.Mutex
	key     *kmspb.CryptoKey
	updates []*kmspb.UpdateCryptoKeyRequest
}

func (f *fakeKMS) GetKeyRing(_ context.Context, r *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error) {
	return &kmspb.KeyRing{Name: r.Name}, nil
}

func (f *fakeKMS) CreateCryptoKey(_ context.Context, r *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.key != nil {
		return nil, grpcstatus.Error(grpccodes.AlreadyExists, "exists")
	}
	ck := r.CryptoKey
	ck.Name = r.Parent + "/cryptoKeys/" + r.CryptoKeyId
	f.key = ck
	return ck, nil
}

// UpdateCryptoKey applies the update mask like Cloud KMS does: every field in
// the mask is replaced by the request value (empty labels clear all labels).
func (f *fakeKMS) UpdateCryptoKey(_ context.Context, r *kmspb.UpdateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(f.updates, r)
	for _, p := range r.UpdateMask.GetPaths() {
		switch p {
		case "labels":
			f.key.Labels = r.CryptoKey.Labels
		case "rotation_period":
			f.key.RotationSchedule = r.CryptoKey.RotationSchedule
		case "next_rotation_time":
			f.key.NextRotationTime = r.CryptoKey.NextRotationTime
		}
	}
	return f.key, nil
}

func (f *fakeKMS) GetCryptoKey(_ context.Context, r *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.key, nil
}

func withFakeKMS(t *testing.T, b *backend) *fakeKMS {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	f := &fakeKMS{}
	kmspb.RegisterKeyManagementServiceServer(srv, f)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	c, err := kmsapi.NewKeyManagementClient(context.Background(),
		option.WithEndpoint(lis.Addr().String()),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	b.kmsClient = c
	b.kmsClientCreateTime = time.Now().UTC()
	return f
}

func testKeysUpdateMask(t *testing.T, update map[string]interface{}) (*fakeKMS, *kmspb.UpdateCryptoKeyRequest) {
	t.Helper()
	b, storage, _ := testBackend(t)
	f := withFakeKMS(t, b)
	ctx := context.Background()

	write := func(op logical.Operation, data map[string]interface{}) {
		t.Helper()
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Storage: storage, Operation: op, Path: "keys/my-key", Data: data,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("op %s: resp=%v err=%v", op, resp, err)
		}
	}
	write(logical.CreateOperation, map[string]interface{}{
		"key_ring": "projects/p/locations/global/keyRings/r",
		"labels":   "team=sec",
	})
	if got := f.key.Labels["team"]; got != "sec" {
		t.Fatalf("after create labels=%v", f.key.Labels)
	}
	update["key_ring"] = "projects/p/locations/global/keyRings/r"
	write(logical.UpdateOperation, update)
	if len(f.updates) > 1 {
		t.Fatalf("expected at most 1 UpdateCryptoKey call, got %d", len(f.updates))
	}
	if len(f.updates) == 0 {
		return f, nil
	}
	return f, f.updates[0]
}

func hasPath(r *kmspb.UpdateCryptoKeyRequest, p string) bool {
	if r == nil {
		return false
	}
	for _, x := range r.UpdateMask.GetPaths() {
		if x == p {
			return true
		}
	}
	return false
}

func TestPathKeys_UpdateMask(t *testing.T) {
	t.Run("rotation_period_only_keeps_labels", func(t *testing.T) {
		f, req := testKeysUpdateMask(t, map[string]interface{}{"rotation_period": "72h"})
		t.Logf("update mask paths=%v", req.UpdateMask.GetPaths())
		if hasPath(req, "labels") {
			t.Errorf("labels not given, but update mask has %q (request labels=%v)", "labels", req.CryptoKey.Labels)
		}
		if !hasPath(req, "rotation_period") || !hasPath(req, "next_rotation_time") {
			t.Errorf("rotation fields missing from mask: %v", req.UpdateMask.GetPaths())
		}
		if f.key.Labels["team"] != "sec" {
			t.Errorf("labels cleared: %v", f.key.Labels)
		}
	})

	t.Run("no_fields_keeps_labels", func(t *testing.T) {
		f, req := testKeysUpdateMask(t, map[string]interface{}{})
		if req != nil {
			t.Logf("update mask paths=%v", req.UpdateMask.GetPaths())
			if hasPath(req, "labels") {
				t.Errorf("labels not given, but update mask has %q", "labels")
			}
			if len(req.UpdateMask.GetPaths()) == 0 {
				t.Errorf("UpdateCryptoKey sent with an empty update mask")
			}
		}
		if f.key.Labels["team"] != "sec" {
			t.Errorf("labels cleared: %v", f.key.Labels)
		}
	})

	t.Run("explicit_labels_are_updated", func(t *testing.T) {
		f, req := testKeysUpdateMask(t, map[string]interface{}{"labels": "team=ops"})
		if !hasPath(req, "labels") {
			t.Errorf("labels given, but missing from mask: %v", req.UpdateMask.GetPaths())
		}
		if f.key.Labels["team"] != "ops" {
			t.Errorf("labels not updated: %v", f.key.Labels)
		}
	})

	t.Run("explicit_empty_labels_clear", func(t *testing.T) {
		f, req := testKeysUpdateMask(t, map[string]interface{}{"labels": map[string]interface{}{}})
		if !hasPath(req, "labels") {
			t.Errorf("empty labels given, but missing from mask: %v", req.UpdateMask.GetPaths())
		}
		if len(f.key.Labels) != 0 {
			t.Errorf("labels not cleared: %v", f.key.Labels)
		}
	})
}
