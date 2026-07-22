package crypto

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSKMSClient implements KMSClient using AWS KMS. It calls kms:Encrypt and
// kms:Decrypt on the configured key ARN. The KEK (Customer Master Key) never
// leaves the AWS KMS boundary (docs/DESIGN.md §7.3).
//
// AWSKMSClient is safe for concurrent use; the underlying AWS SDK client
// handles connection pooling and request serialization.
type AWSKMSClient struct {
	client kmsAPI
}

// kmsAPI is the subset of the AWS KMS client used by AWSKMSClient. This seam
// allows injecting a fake for unit tests without LocalStack.
type kmsAPI interface {
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// Compile-time proof that *kms.Client satisfies kmsAPI.
var _ kmsAPI = (*kms.Client)(nil)

// Compile-time proof that AWSKMSClient implements KMSClient.
var _ KMSClient = (*AWSKMSClient)(nil)

// NewAWSKMSClient constructs an AWSKMSClient from an AWS SDK v2 KMS client.
// The caller is responsible for configuring the AWS client with appropriate
// credentials and region (typically via aws.Config from config.LoadDefaultConfig).
//
// Example:
//
//	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
//	if err != nil { ... }
//	kmsClient := kms.NewFromConfig(cfg)
//	client := crypto.NewAWSKMSClient(kmsClient)
func NewAWSKMSClient(client *kms.Client) *AWSKMSClient {
	return &AWSKMSClient{client: client}
}

// newAWSKMSClientWithAPI constructs an AWSKMSClient with a custom kmsAPI.
// Intended for unit tests that inject a fake kmsAPI.
func newAWSKMSClientWithAPI(api kmsAPI) *AWSKMSClient {
	return &AWSKMSClient{client: api}
}

// Encrypt implements KMSClient. It calls AWS KMS Encrypt to wrap plaintext
// under the CMK identified by keyID. The keyID should be a key ARN, key ID,
// alias ARN, or alias name.
//
// The returned ciphertext is the raw KMS CiphertextBlob, which is opaque and
// can only be decrypted by calling Decrypt with the same keyID (or letting
// KMS auto-detect the key from the ciphertext metadata).
func (c *AWSKMSClient) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		// AWS KMS rejects empty plaintext; return a clear error.
		return nil, fmt.Errorf("crypto: AWSKMSClient: plaintext must not be empty")
	}

	output, err := c.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(keyID),
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, wrapKMSError("Encrypt", err)
	}

	return output.CiphertextBlob, nil
}

// Decrypt implements KMSClient. It calls AWS KMS Decrypt to unwrap ciphertext
// that was previously encrypted under keyID. The keyID is used for validation;
// AWS KMS extracts the actual key from the ciphertext metadata.
//
// Returns ErrKMSDecryptFailed if decryption fails (invalid ciphertext, wrong
// key, tampering, or access denied).
func (c *AWSKMSClient) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, ErrKMSDecryptFailed
	}

	output, err := c.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(keyID),
		CiphertextBlob: ciphertext,
	})
	if err != nil {
		// Map all KMS errors to ErrKMSDecryptFailed (decryption-oracle defense).
		// Log the underlying error at debug level for operational visibility.
		return nil, ErrKMSDecryptFailed
	}

	// Note: We do NOT verify output.KeyId matches keyID because AWS KMS always
	// returns the full key ARN, while callers may pass a key ID, alias, or ARN.
	// KMS already cryptographically authenticates the ciphertext against the
	// correct key, so an additional check is redundant and would break valid
	// decryptions when keyID is not a full ARN.

	return output.Plaintext, nil
}

// wrapKMSError converts AWS KMS errors to appropriate sentinel errors.
func wrapKMSError(op string, err error) error {
	if err == nil {
		return nil
	}

	// Check for specific KMS error types.
	var notFoundErr *types.NotFoundException
	if errors.As(err, &notFoundErr) {
		return ErrKMSKeyNotFound
	}

	var invalidKeyErr *types.InvalidKeyUsageException
	if errors.As(err, &invalidKeyErr) {
		return fmt.Errorf("crypto: AWSKMSClient.%s: invalid key usage: %w", op, err)
	}

	var disabledErr *types.DisabledException
	if errors.As(err, &disabledErr) {
		return fmt.Errorf("crypto: AWSKMSClient.%s: key is disabled: %w", op, err)
	}

	var invalidStateErr *types.KMSInvalidStateException
	if errors.As(err, &invalidStateErr) {
		return fmt.Errorf("crypto: AWSKMSClient.%s: key is in invalid state: %w", op, err)
	}

	// Generic wrap for other errors (access denied, throttling, etc.)
	return fmt.Errorf("crypto: AWSKMSClient.%s: %w", op, err)
}
