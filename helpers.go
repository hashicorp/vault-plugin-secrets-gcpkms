package gcpkms

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// withFieldValidator wraps an OperationFunc and validates the user-supplied
// fields match the schema.
func withFieldValidator(f framework.OperationFunc) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		if err := validateFields(req, d); err != nil {
			return nil, logical.CodedError(422, err.Error())
		}
		return f(ctx, req, d)
	}
}

// validateFields verifies that no bad arguments were given to the request.
func validateFields(req *logical.Request, data *framework.FieldData) error {
	var unknownFields []string
	for k := range req.Data {
		if _, ok := data.Schema[k]; !ok {
			unknownFields = append(unknownFields, k)
		}
	}

	switch len(unknownFields) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("unknown field: %s", unknownFields[0])
	default:
		sort.Strings(unknownFields)
		return fmt.Errorf("unknown fields: %s", strings.Join(unknownFields, ","))
	}
}

// errMissingFields is a helper to return an error when required fields are
// missing.
func errMissingFields(f ...string) error {
	return logical.CodedError(422, fmt.Sprintf(
		"missing required field(s): %q", f))
}
