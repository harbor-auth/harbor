package crypto

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// --- Mock kmsAPI for unit tests ---

type mockKMSAPI struct {
	encryptFunc func(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	decryptFunc func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

func (m *mockKMSAPI) Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(ctx, params, optFns...)
	}
	return nil, errors.New("encryptFunc not set")
}

func (m *mockKMSAPI) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(ctx, params, optFns...)
	}
	return nil, errors.New("decryptFunc not set")
}

var _ kmsAPI = (*mockKMSAPI)(nil)

// --- Unit tests with mock ---

func TestAWSKMSClientEncryptSuccess(t *testing.T) {
	ctx := context.Background()
	keyID := "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
	plaintext := []byte("secret data")
	expectedCiphertext := []byte("encrypted-blob")

	mock := &mockKMSAPI{
		encryptFunc: func(_ context.Context, params *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			if *params.KeyId != keyID {
				t.Errorf("KeyId = %q, want %q", *params.KeyId, keyID)
			}
			if string(params.Plaintext) != string(plaintext) {
				t.Errorf("Plaintext mismatch")
			}
			return &kms.EncryptOutput{
				CiphertextBlob: expectedCiphertext,
				KeyId:          aws.String(keyID),
			}, nil
		},
	}

	client := newAWSKMSClientWithAPI(mock)
	ct, err := client.Encrypt(ctx, keyID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(ct) != string(expectedCiphertext) {
		t.Fatalf("ciphertext = %q, want %q", ct, expectedCiphertext)
	}
}

func TestAWSKMSClientEncryptEmptyPlaintext(t *testing.T) {
	ctx := context.Background()
	client := newAWSKMSClientWithAPI(&mockKMSAPI{})

	_, err := client.Encrypt(ctx, "some-key", []byte{})
	if err == nil {
		t.Fatal("expected error for empty plaintext, got nil")
	}
}

func TestAWSKMSClientEncryptKeyNotFound(t *testing.T) {
	ctx := context.Background()
	mock := &mockKMSAPI{
		encryptFunc: func(_ context.Context, _ *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			return nil, &types.NotFoundException{Message: aws.String("key not found")}
		},
	}

	client := newAWSKMSClientWithAPI(mock)
	_, err := client.Encrypt(ctx, "nonexistent-key", []byte("data"))
	if !errors.Is(err, ErrKMSKeyNotFound) {
		t.Fatalf("error = %v, want ErrKMSKeyNotFound", err)
	}
}

func TestAWSKMSClientDecryptSuccess(t *testing.T) {
	ctx := context.Background()
	keyID := "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
	ciphertext := []byte("encrypted-blob")
	expectedPlaintext := []byte("secret data")

	mock := &mockKMSAPI{
		decryptFunc: func(_ context.Context, params *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			if *params.KeyId != keyID {
				t.Errorf("KeyId = %q, want %q", *params.KeyId, keyID)
			}
			return &kms.DecryptOutput{
				Plaintext: expectedPlaintext,
				KeyId:     aws.String(keyID),
			}, nil
		},
	}

	client := newAWSKMSClientWithAPI(mock)
	pt, err := client.Decrypt(ctx, keyID, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != string(expectedPlaintext) {
		t.Fatalf("plaintext = %q, want %q", pt, expectedPlaintext)
	}
}

func TestAWSKMSClientDecryptEmptyCiphertext(t *testing.T) {
	ctx := context.Background()
	client := newAWSKMSClientWithAPI(&mockKMSAPI{})

	_, err := client.Decrypt(ctx, "some-key", []byte{})
	if !errors.Is(err, ErrKMSDecryptFailed) {
		t.Fatalf("error = %v, want ErrKMSDecryptFailed", err)
	}
}

func TestAWSKMSClientDecryptError(t *testing.T) {
	ctx := context.Background()
	mock := &mockKMSAPI{
		decryptFunc: func(_ context.Context, _ *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			return nil, errors.New("decryption failed")
		},
	}

	client := newAWSKMSClientWithAPI(mock)
	_, err := client.Decrypt(ctx, "some-key", []byte("ciphertext"))
	if !errors.Is(err, ErrKMSDecryptFailed) {
		t.Fatalf("error = %v, want ErrKMSDecryptFailed", err)
	}
}

func TestAWSKMSClientEncryptDisabledKey(t *testing.T) {
	ctx := context.Background()
	mock := &mockKMSAPI{
		encryptFunc: func(_ context.Context, _ *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			return nil, &types.DisabledException{Message: aws.String("key is disabled")}
		},
	}

	client := newAWSKMSClientWithAPI(mock)
	_, err := client.Encrypt(ctx, "disabled-key", []byte("data"))
	if err == nil {
		t.Fatal("expected error for disabled key, got nil")
	}
	// Should wrap but not be ErrKMSKeyNotFound
	if errors.Is(err, ErrKMSKeyNotFound) {
		t.Fatal("disabled key should not return ErrKMSKeyNotFound")
	}
}

func TestAWSKMSClientEncryptInvalidKeyUsage(t *testing.T) {
	ctx := context.Background()
	mock := &mockKMSAPI{
		encryptFunc: func(_ context.Context, _ *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
			return nil, &types.InvalidKeyUsageException{Message: aws.String("key cannot encrypt")}
		},
	}

	client := newAWSKMSClientWithAPI(mock)
	_, err := client.Encrypt(ctx, "sign-only-key", []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid key usage, got nil")
	}
}

// --- LocalStack integration tests ---

// TestAWSKMSClientLocalStackIntegration runs against LocalStack when LOCALSTACK_ENDPOINT
// is set (e.g., http://localhost:4566). Skip in normal CI; run manually or in
// e2e environments with LocalStack available.
func TestAWSKMSClientLocalStackIntegration(t *testing.T) {
	endpoint := os.Getenv("LOCALSTACK_ENDPOINT")
	if endpoint == "" {
		t.Skip("LOCALSTACK_ENDPOINT not set; skipping LocalStack integration test")
	}

	ctx := context.Background()

	// Configure AWS SDK to use LocalStack
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			"test", "test", "",
		)),
	)
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}

	// Create KMS client pointing to LocalStack
	kmsClient := kms.NewFromConfig(cfg, func(o *kms.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})

	// Create a test key in LocalStack
	createKeyOutput, err := kmsClient.CreateKey(ctx, &kms.CreateKeyInput{
		Description: aws.String("Test key for Harbor crypto integration tests"),
		KeyUsage:    types.KeyUsageTypeEncryptDecrypt,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyID := *createKeyOutput.KeyMetadata.KeyId
	t.Logf("Created LocalStack KMS key: %s", keyID)

	// Test AWSKMSClient
	client := NewAWSKMSClient(kmsClient)

	// Test encrypt/decrypt round-trip
	plaintext := []byte("secret data for LocalStack test")
	ciphertext, err := client.Encrypt(ctx, keyID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}

	decrypted, err := client.Decrypt(ctx, keyID, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}

	t.Log("LocalStack KMS integration test passed")
}
