package crypto

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// OpenBaoKMSConfig configures an OpenBao Transit client authenticated through
// OpenBao's Kubernetes auth method. The projected service-account token is
// exchanged for a short-lived OpenBao token; no durable OpenBao token is stored
// in the Harbor pod.
type OpenBaoKMSConfig struct {
	Address       string
	Role          string
	TokenPath     string
	CACertPath    string
	TransitMount  string
	HTTPClient    *http.Client
	AllowInsecure bool // tests only; production configuration must use HTTPS
}

// OpenBaoKMSClient implements KMSClient with the OpenBao Transit secrets engine.
// Transit performs cryptographic operations without returning the named key.
type OpenBaoKMSClient struct {
	address      string
	role         string
	tokenPath    string
	transitMount string
	httpClient   *http.Client

	mu          sync.Mutex
	clientToken string
	tokenExpiry time.Time
}

var _ KMSClient = (*OpenBaoKMSClient)(nil)

// NewOpenBaoKMSClient validates the endpoint and constructs a TLS-verifying
// OpenBao Transit client.
func NewOpenBaoKMSClient(cfg OpenBaoKMSConfig) (*OpenBaoKMSClient, error) {
	address := strings.TrimRight(strings.TrimSpace(cfg.Address), "/")
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" {
		return nil, errors.New("crypto: OpenBao address is invalid")
	}
	if parsed.Scheme != "https" && !cfg.AllowInsecure {
		return nil, errors.New("crypto: OpenBao address must use HTTPS")
	}
	if parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("crypto: OpenBao address must not contain credentials, a path, query, or fragment")
	}
	if strings.TrimSpace(cfg.Role) == "" {
		return nil, errors.New("crypto: OpenBao Kubernetes auth role is required")
	}
	if strings.TrimSpace(cfg.TokenPath) == "" {
		return nil, errors.New("crypto: OpenBao service-account token path is required")
	}

	mount := strings.Trim(strings.TrimSpace(cfg.TransitMount), "/")
	if mount == "" {
		mount = "transit"
	}
	if strings.Contains(mount, "/") {
		return nil, errors.New("crypto: OpenBao Transit mount must be one path segment")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CACertPath != "" {
			pem, readErr := os.ReadFile(cfg.CACertPath)
			if readErr != nil {
				return nil, fmt.Errorf("crypto: read OpenBao CA certificate: %w", readErr)
			}
			roots, rootsErr := x509.SystemCertPool()
			if rootsErr != nil {
				roots = x509.NewCertPool()
			}
			if roots == nil {
				roots = x509.NewCertPool()
			}
			if !roots.AppendCertsFromPEM(pem) {
				return nil, errors.New("crypto: OpenBao CA certificate is invalid")
			}
			tlsConfig.RootCAs = roots
		}
		transport.TLSClientConfig = tlsConfig
		httpClient = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	}

	return &OpenBaoKMSClient{
		address:      address,
		role:         cfg.Role,
		tokenPath:    cfg.TokenPath,
		transitMount: mount,
		httpClient:   httpClient,
	}, nil
}

// Encrypt wraps plaintext with the named Transit key.
func (c *OpenBaoKMSClient) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, ErrKMSKeyNotFound
	}
	if len(plaintext) == 0 {
		return nil, errors.New("crypto: OpenBaoKMSClient: plaintext must not be empty")
	}

	var response struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	status, err := c.authedPost(ctx,
		"/v1/"+url.PathEscape(c.transitMount)+"/encrypt/"+url.PathEscape(keyID),
		map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)},
		&response,
	)
	if err != nil {
		if status == http.StatusNotFound {
			return nil, ErrKMSKeyNotFound
		}
		return nil, fmt.Errorf("crypto: OpenBaoKMSClient.Encrypt: %w", err)
	}
	if response.Data.Ciphertext == "" {
		return nil, errors.New("crypto: OpenBaoKMSClient.Encrypt: empty ciphertext")
	}
	return []byte(response.Data.Ciphertext), nil
}

// Decrypt unwraps a Transit ciphertext. Every failure is collapsed to the
// generic sentinel to avoid exposing a decryption oracle.
func (c *OpenBaoKMSClient) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	if strings.TrimSpace(keyID) == "" || len(ciphertext) == 0 {
		return nil, ErrKMSDecryptFailed
	}

	var response struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	_, err := c.authedPost(ctx,
		"/v1/"+url.PathEscape(c.transitMount)+"/decrypt/"+url.PathEscape(keyID),
		map[string]string{"ciphertext": string(ciphertext)},
		&response,
	)
	if err != nil || response.Data.Plaintext == "" {
		return nil, ErrKMSDecryptFailed
	}
	plaintext, err := base64.StdEncoding.DecodeString(response.Data.Plaintext)
	if err != nil {
		return nil, ErrKMSDecryptFailed
	}
	return plaintext, nil
}

func (c *OpenBaoKMSClient) authedPost(ctx context.Context, path string, input, output any) (int, error) {
	token, err := c.token(ctx)
	if err != nil {
		return 0, err
	}
	status, err := c.post(ctx, path, token, input, output)
	if status == http.StatusForbidden {
		// The cached token may have been revoked early. Invalidate it and retry
		// once with a fresh Kubernetes login.
		c.mu.Lock()
		c.clientToken = ""
		c.tokenExpiry = time.Time{}
		c.mu.Unlock()
		token, loginErr := c.token(ctx)
		if loginErr != nil {
			return status, loginErr
		}
		return c.post(ctx, path, token, input, output)
	}
	return status, err
}

func (c *OpenBaoKMSClient) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clientToken != "" && time.Now().Add(30*time.Second).Before(c.tokenExpiry) {
		return c.clientToken, nil
	}

	jwt, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return "", fmt.Errorf("read projected Kubernetes token: %w", err)
	}
	var response struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	_, err = c.post(ctx, "/v1/auth/kubernetes/login", "", map[string]string{
		"role": c.role,
		"jwt":  strings.TrimSpace(string(jwt)),
	}, &response)
	if err != nil {
		return "", fmt.Errorf("OpenBao Kubernetes login: %w", err)
	}
	if response.Auth.ClientToken == "" || response.Auth.LeaseDuration <= 0 {
		return "", errors.New("OpenBao Kubernetes login returned an invalid token lease")
	}
	c.clientToken = response.Auth.ClientToken
	c.tokenExpiry = time.Now().Add(time.Duration(response.Auth.LeaseDuration) * time.Second)
	return c.clientToken, nil
}

func (c *OpenBaoKMSClient) post(ctx context.Context, path, token string, input, output any) (int, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.address+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Request", "true")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, fmt.Errorf("OpenBao returned HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(output); err != nil {
		return resp.StatusCode, err
	}
	return resp.StatusCode, nil
}
