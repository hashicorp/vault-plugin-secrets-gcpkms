// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: BUSL-1.1

package gcpkms

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// mockBillingManager captures WriteBillingData calls for assertion in tests.
type mockBillingManager struct {
	calls []map[string]interface{}
}

func (m *mockBillingManager) WriteBillingData(_ context.Context, _ string, data map[string]interface{}) error {
	m.calls = append(m.calls, data)
	return nil
}

// mountReq builds a minimal logical.Request populated with mount metadata,
// sufficient to exercise accumulateGcpkmsAttributions and
// incrementBillingDataCount without a live KMS client.
func mountReq(path, mountAccessor, mountPoint, mountType string) *logical.Request {
	return &logical.Request{
		Path:          path,
		MountAccessor: mountAccessor,
		MountPoint:    mountPoint,
		MountType:     mountType,
	}
}

// TestMountAttribution_Decrypt verifies that the decrypt path records
// attribution keyed by MountAccessor and writes billing data.
func TestMountAttribution_Decrypt(t *testing.T) {
	b, _ := testBackend(t)
	mock := &mockBillingManager{}
	b.ConsumptionBillingManager = mock

	req := mountReq("decrypt/my-key", "auth_abc123", "gcpkms/", "gcpkms")

	err := b.incrementBillingDataCount(context.Background(), req, 1)
	require.NoError(t, err)

	verifyGcpkmsAttribution(t, b, "auth_abc123", "gcpkms/", 1)
	require.Equal(t, uint64(1), b.billingDataCounts.Load())
	require.Len(t, mock.calls, 1)
	require.Equal(t, "auth_abc123", mock.calls[0]["mountAccessor"])
	require.Equal(t, "gcpkms/", mock.calls[0]["mountPath"])
}

// TestMountAttribution_Encrypt verifies that the encrypt path records
// attribution keyed by MountAccessor and writes billing data.
func TestMountAttribution_Encrypt(t *testing.T) {
	b, _ := testBackend(t)
	mock := &mockBillingManager{}
	b.ConsumptionBillingManager = mock

	req := mountReq("encrypt/my-key", "auth_abc123", "gcpkms/", "gcpkms")

	err := b.incrementBillingDataCount(context.Background(), req, 1)
	require.NoError(t, err)

	verifyGcpkmsAttribution(t, b, "auth_abc123", "gcpkms/", 1)
	require.Equal(t, uint64(1), b.billingDataCounts.Load())
	require.Len(t, mock.calls, 1)
	require.Equal(t, "auth_abc123", mock.calls[0]["mountAccessor"])
	require.Equal(t, "gcpkms/", mock.calls[0]["mountPath"])
}

// TestMountAttribution_Reencrypt verifies that the reencrypt path records
// attribution keyed by MountAccessor and writes billing data.
func TestMountAttribution_Reencrypt(t *testing.T) {
	b, _ := testBackend(t)
	mock := &mockBillingManager{}
	b.ConsumptionBillingManager = mock

	req := mountReq("reencrypt/my-key", "auth_abc123", "gcpkms/", "gcpkms")

	err := b.incrementBillingDataCount(context.Background(), req, 1)
	require.NoError(t, err)

	verifyGcpkmsAttribution(t, b, "auth_abc123", "gcpkms/", 1)
	require.Equal(t, uint64(1), b.billingDataCounts.Load())
	require.Len(t, mock.calls, 1)
	require.Equal(t, "auth_abc123", mock.calls[0]["mountAccessor"])
	require.Equal(t, "gcpkms/", mock.calls[0]["mountPath"])
}

// TestMountAttribution_Sign verifies that the sign path records
// attribution keyed by MountAccessor and writes billing data.
func TestMountAttribution_Sign(t *testing.T) {
	b, _ := testBackend(t)
	mock := &mockBillingManager{}
	b.ConsumptionBillingManager = mock

	req := mountReq("sign/my-key", "auth_abc123", "gcpkms/", "gcpkms")

	err := b.incrementBillingDataCount(context.Background(), req, 1)
	require.NoError(t, err)

	verifyGcpkmsAttribution(t, b, "auth_abc123", "gcpkms/", 1)
	require.Equal(t, uint64(1), b.billingDataCounts.Load())
	require.Len(t, mock.calls, 1)
	require.Equal(t, "auth_abc123", mock.calls[0]["mountAccessor"])
	require.Equal(t, "gcpkms/", mock.calls[0]["mountPath"])
}

// TestMountAttribution_Verify verifies that the verify path records
// attribution keyed by MountAccessor and writes billing data.
func TestMountAttribution_Verify(t *testing.T) {
	b, _ := testBackend(t)
	mock := &mockBillingManager{}
	b.ConsumptionBillingManager = mock

	req := mountReq("verify/my-key", "auth_abc123", "gcpkms/", "gcpkms")

	err := b.incrementBillingDataCount(context.Background(), req, 1)
	require.NoError(t, err)

	verifyGcpkmsAttribution(t, b, "auth_abc123", "gcpkms/", 1)
	require.Equal(t, uint64(1), b.billingDataCounts.Load())
	require.Len(t, mock.calls, 1)
	require.Equal(t, "auth_abc123", mock.calls[0]["mountAccessor"])
	require.Equal(t, "gcpkms/", mock.calls[0]["mountPath"])
}

// TestMountAttribution_Cumulative verifies that repeated calls across all five
// paths on the same mount accessor accumulate the count correctly.
func TestMountAttribution_Cumulative(t *testing.T) {
	b, _ := testBackend(t)
	mock := &mockBillingManager{}
	b.ConsumptionBillingManager = mock

	paths := []string{
		"decrypt/my-key",
		"encrypt/my-key",
		"reencrypt/my-key",
		"sign/my-key",
		"verify/my-key",
	}

	for _, p := range paths {
		req := mountReq(p, "auth_abc123", "gcpkms/", "gcpkms")
		require.NoError(t, b.incrementBillingDataCount(context.Background(), req, 1))
	}

	verifyGcpkmsAttribution(t, b, "auth_abc123", "gcpkms/", uint64(len(paths)))
	require.Equal(t, uint64(len(paths)), b.billingDataCounts.Load())
	require.Len(t, mock.calls, len(paths))
}

// TestMountAttribution_MultipleMounts verifies that attributions for distinct
// mount accessors are tracked independently.
func TestMountAttribution_MultipleMounts(t *testing.T) {
	b, _ := testBackend(t)
	mock := &mockBillingManager{}
	b.ConsumptionBillingManager = mock

	mounts := []struct {
		accessor   string
		mountPoint string
		path       string
		count      uint64
	}{
		{"accessor_aaa", "gcpkms-a/", "encrypt/my-key", 2},
		{"accessor_bbb", "gcpkms-b/", "decrypt/my-key", 3},
	}

	for _, m := range mounts {
		req := mountReq(m.path, m.accessor, m.mountPoint, "gcpkms")
		var i uint64
		for i = 0; i < m.count; i++ {
			require.NoError(t, b.incrementBillingDataCount(context.Background(), req, 1))
		}
	}

	for _, m := range mounts {
		verifyGcpkmsAttribution(t, b, m.accessor, m.mountPoint, m.count)
	}
	require.Len(t, mock.calls, 5) // 2 + 3
}

// TestMountAttribution_EmptyAccessor verifies that an empty MountAccessor
// causes incrementBillingDataCount to still write billing data (without
// attribution) and does not create an attribution entry.
func TestMountAttribution_EmptyAccessor(t *testing.T) {
	b, _ := testBackend(t)
	mock := &mockBillingManager{}
	b.ConsumptionBillingManager = mock

	req := mountReq("encrypt/my-key", "", "gcpkms/", "gcpkms")

	err := b.incrementBillingDataCount(context.Background(), req, 1)
	require.NoError(t, err)

	verifyNoGcpkmsAttribution(t, b, "")
	require.Equal(t, uint64(1), b.billingDataCounts.Load())
	require.Len(t, mock.calls, 1)
}
