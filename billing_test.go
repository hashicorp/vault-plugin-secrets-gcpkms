// Copyright IBM Corp. 2018, 2026

package gcpkms

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// mockConsumptionBillingManager is a test fake for logical.ConsumptionBillingManager.
// It records all WriteBillingData calls so tests can assert on them.
type mockConsumptionBillingManager struct {
	mu          sync.Mutex
	totalCount  atomic.Uint64
	attribution map[string]logical.MountAttribution
}

func newMockConsumptionBillingManager() *mockConsumptionBillingManager {
	return &mockConsumptionBillingManager{
		attribution: make(map[string]logical.MountAttribution),
	}
}

func (f *mockConsumptionBillingManager) WriteBillingData(_ context.Context, _ string, data map[string]interface{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	count, _ := data["count"].(uint64)
	mountAccessor, _ := data["mountAccessor"].(string)
	mountPath, _ := data["mountPath"].(string)
	mountType, _ := data["mountType"].(string)
	backendAwareUUID, _ := data["backendAwareUUID"].(string)

	f.totalCount.Add(count)

	var prev uint64
	if existing, ok := f.attribution[mountAccessor]; ok {
		if n, ok := existing.Count.(uint64); ok {
			prev = n
		}
	}
	f.attribution[mountAccessor] = logical.MountAttribution{
		MountPath:        mountPath,
		MountAccessor:    mountAccessor,
		MountType:        mountType,
		BackendAwareUUID: backendAwareUUID,
		Count:            prev + count,
	}
	return nil
}

func verifyGcpkmsAttribution(t *testing.T, f *mockConsumptionBillingManager, mountAccessor, mountPath string, expectedCount uint64) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	attribution, ok := f.attribution[mountAccessor]
	require.True(t, ok, "Expected attribution entry for %s", mountAccessor)
	require.Equal(t, uint64(expectedCount), attribution.Count, "count mismatch")
	require.Equal(t, mountPath, attribution.MountPath, "mountPath mismatch")
	require.Equal(t, mountAccessor, attribution.MountAccessor, "mountAccessor mismatch")
}

func verifyNoGcpkmsAttribution(t *testing.T, f *mockConsumptionBillingManager, mountAccessor string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.attribution[mountAccessor]
	require.False(t, ok, "Expected no attribution entry for %s", mountAccessor)
}
