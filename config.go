// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms

import (
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/helper/pluginidentityutil"
)

const (
	defaultScope = "https://www.googleapis.com/auth/cloudkms"
)

// Config is the stored configuration.
type Config struct {
	Credentials         string   `json:"credentials"`
	Scopes              []string `json:"scopes"`
	ServiceAccountEmail string   `json:"service_account_email"`
	pluginidentityutil.PluginIdentityTokenParams
	automatedrotationutil.AutomatedRotationParams
}

// DefaultConfig returns a config with the default values.
func DefaultConfig() *Config {
	return &Config{
		Scopes: []string{defaultScope},
	}
}
