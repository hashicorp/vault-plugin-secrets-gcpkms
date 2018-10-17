package gcpkms

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/useragent"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"

	kmsapi "cloud.google.com/go/kms/apiv1"
)

var (
	// defaultClientLifetime is the amount of time to cache the KMS client. This
	// has to be less than 60 minutes or the oauth token will expire and
	// subsequent requests will fail. The reason we cache the client is because
	// the process for looking up credentials is not performant and the overhead
	// is too significant for a plugin that will receive this much traffic.
	defaultClientLifetime = 30 * time.Minute
)

type backend struct {
	*framework.Backend

	// kmsClient is the actual client for connecting to KMS. It is cached on
	// the backend for efficiency.
	kmsClient           *kmsapi.KeyManagementClient
	kmsClientCreateTime time.Time
	kmsClientLifetime   time.Duration
	kmsClientMutex      sync.RWMutex
}

// Factory returns a configured instance of the backend.
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend returns a configured instance of the backend.
func Backend() *backend {
	var b backend

	b.kmsClientLifetime = defaultClientLifetime

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help: "The GCP KMS secrets engine provides pass-through encryption and " +
			"decryption to Google Cloud KMS keys.",
		Paths: []*framework.Path{
			b.pathConfig(),

			b.pathKeys(),
			b.pathKeysCRUD(),
			b.pathKeysConfigCRUD(),
			b.pathKeysDeregister(),
			b.pathKeysRegister(),
			b.pathKeysRotate(),
			b.pathKeysTrim(),

			b.pathDecrypt(),
			b.pathEncrypt(),
			b.pathReencrypt(),
			b.pathSign(),
			b.pathVerify(),
		},
	}

	return &b
}

// ResetClient closes any connected clients.
func (b *backend) ResetClient() {
	b.kmsClientMutex.Lock()
	b.resetClient()
	b.kmsClientMutex.Unlock()
}

// KMSClient creates a new client for talking to the GCP KMS service.
func (b *backend) KMSClient(ctx context.Context, s logical.Storage) (*kmsapi.KeyManagementClient, func(), error) {
	// If the client already exists and is valid, return it
	b.kmsClientMutex.RLock()
	if b.kmsClient != nil && time.Now().UTC().Sub(b.kmsClientCreateTime) < b.kmsClientLifetime {
		closer := func() { b.kmsClientMutex.RUnlock() }
		return b.kmsClient, closer, nil
	}
	b.kmsClientMutex.RUnlock()

	// Acquire a full lock. Since all invocations acquire a read lock and defer
	// the release of that lock, this will block until all clients are no longer
	// in use. At that point, we can acquire a globally exclusive lock to close
	// any connections and create a new client.
	b.kmsClientMutex.Lock()

	b.Logger().Debug("creating new KMS client")

	// Attempt to close an existing client if we have one.
	b.resetClient()

	// Get the config
	config, err := b.Config(ctx, s)
	if err != nil {
		b.kmsClientMutex.Unlock()
		return nil, nil, nil
	}

	// If credentials were provided, use those. Otherwise fall back to the
	// default application credentials.
	var creds *google.Credentials
	if config != nil && config.Credentials != "" {
		ctx := context.Background()
		creds, err = google.CredentialsFromJSON(ctx, []byte(config.Credentials), config.Scopes...)
		if err != nil {
			b.kmsClientMutex.Unlock()
			return nil, nil, errwrap.Wrapf("failed to parse credentials: {{err}}", err)
		}
	} else {
		ctx := context.Background()
		creds, err = google.FindDefaultCredentials(ctx, config.Scopes...)
		if err != nil {
			b.kmsClientMutex.Unlock()
			return nil, nil, errwrap.Wrapf("failed to get default token source: {{err}}", err)
		}
	}

	// Create and return the KMS client with a custom user agent.
	ctx = context.Background()
	client, err := kmsapi.NewKeyManagementClient(ctx,
		option.WithCredentials(creds),
		option.WithScopes(config.Scopes...),
		option.WithUserAgent(useragent.String()),
	)
	if err != nil {
		b.kmsClientMutex.Unlock()
		return nil, nil, errwrap.Wrapf("failed to create KMS client: {{err}}", err)
	}

	// Cache the client
	b.kmsClient = client
	b.kmsClientCreateTime = time.Now().UTC()
	b.kmsClientMutex.Unlock()

	b.kmsClientMutex.RLock()
	closer := func() { b.kmsClientMutex.RUnlock() }
	return client, closer, nil
}

// Config parses and returns the configuration data from the storage backend.
func (b *backend) Config(ctx context.Context, s logical.Storage) (*Config, error) {
	c := DefaultConfig()

	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, errwrap.Wrapf("failed to get configuration from storage: {{err}}", err)
	}
	if entry == nil || len(entry.Value) == 0 {
		return c, nil
	}

	if err := entry.DecodeJSON(&c); err != nil {
		return nil, errwrap.Wrapf("failed to decode configuration: {{err}}", err)
	}
	return c, nil
}

// resetClient rests the underlying client. The caller is responsible for
// acquiring and releasing locks. This method is not safe to call concurrently.
func (b *backend) resetClient() {
	if b.kmsClient != nil {
		b.kmsClient.Close()
		b.kmsClient = nil
	}

	b.kmsClientCreateTime = time.Unix(0, 0).UTC()
}
