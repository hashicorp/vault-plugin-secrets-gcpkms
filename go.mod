module github.com/hashicorp/vault-plugin-secrets-gcpkms

go 1.12

require (
	cloud.google.com/go/kms v1.1.0
	github.com/gammazero/workerpool v1.1.2
	github.com/golang/protobuf v1.5.2
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.1
	github.com/hashicorp/vault/api v1.3.0
	github.com/hashicorp/vault/sdk v0.3.0
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/jeffchao/backoff v0.0.0-20140404060208-9d7fd7aa17f2
	github.com/satori/go.uuid v1.2.0
	golang.org/x/oauth2 v0.0.0-20211028175245-ba495a64dcb5
	google.golang.org/api v0.59.0
	google.golang.org/genproto v0.0.0-20211028162531-8db9c33dc351
	google.golang.org/grpc v1.41.0
)
