// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: BUSL-1.1

package gcpkms

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Helper function to verify GcpkmsAttribution contains expected values namesapce, mount, and count values
func verifyGcpkmsAttribution(t *testing.T, b *backend, mountAccessor, mountPath string, expectedCount uint64) {
	t.Helper()

	attribution, ok := b.billingDataAttribution[mountAccessor]

	require.True(t, ok, "Expected GcpkmsAttribution to contain entry for %s", mountAccessor)
	require.Equal(t, uint64(expectedCount), attribution.Count, "count mismatch")
	require.Equal(t, mountPath, attribution.MountPath, "mountPath mismatch")
	require.Equal(t, mountAccessor, attribution.MountAccessor, "mountAccessor mismatch")
}

// Helper function to verify GcpkmsAttribution does NOT contain an entry for the given mount accessor
func verifyNoGcpkmsAttribution(t *testing.T, b *backend, mountAccessor string) {
	t.Helper()

	_, ok := b.billingDataAttribution[mountAccessor]

	require.False(t, ok, "Expected GcpkmsAttribution to NOT contain entry for %s", mountAccessor)
}
