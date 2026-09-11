package signup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	smtp "github.com/emersion/go-smtp"
)

type smtpCapture struct {
	message chan string
	tls     bool
}

func (s *smtpCapture) Reset()                               {}
func (s *smtpCapture) Logout() error                        { return nil }
func (s *smtpCapture) Mail(string, *smtp.MailOptions) error { return nil }
func (s *smtpCapture) Rcpt(string, *smtp.RcptOptions) error { return nil }
func (s *smtpCapture) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	if s.tls {
		s.message <- string(b)
	}
	return err
}
func TestSMTPMailerTLSAndDelivery(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-smtp"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, mode := range []string{"trusted", "untrusted", "plaintext"} {
		t.Run(mode, func(t *testing.T) {
			messages := make(chan string, 1)
			server := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
				_, secured := c.TLSConnectionState()
				return &smtpCapture{messages, secured}, nil
			}))
			if mode != "plaintext" {
				server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() { finished <- server.Serve(listener) }()
			defer func() {
				if err := server.Close(); err != nil {
					t.Error(err)
				}
				<-finished
			}()
			mailer, err := NewSMTPMailer(listener.Addr().String(), "signup@harbor.example", "", "")
			if err != nil {
				t.Fatal(err)
			}
			if mode == "trusted" {
				mailer.roots = roots
			}
			err = mailer.SendCode(context.Background(), "person@example.com", "12345678")
			if mode != "trusted" {
				if err == nil {
					t.Fatal("untrusted/plaintext SMTP accepted")
				}
				select {
				case <-messages:
					t.Fatal("code disclosed without trusted TLS")
				default:
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case message := <-messages:
				if !strings.Contains(message, "signup code is: 12345678") || !strings.Contains(message, "To: person@example.com") {
					t.Fatal("mail content missing")
				}
			default:
				t.Fatal("message not delivered over TLS")
			}
		})
	}
}
func TestSMTPConfigurationAndDeadline(t *testing.T) {
	for _, args := range [][4]string{{"", "signup@example.com", "", ""}, {"localhost:587", "bad", "", ""}, {"localhost:587", "signup@example.com", "user", ""}} {
		if _, err := NewSMTPMailer(args[0], args[1], args[2], args[3]); err == nil {
			t.Fatalf("accepted invalid SMTP configuration: %v", args)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			defer func() {
				if err := conn.Close(); err != nil {
					t.Error(err)
				}
			}()
			if _, err := io.Copy(io.Discard, conn); err != nil {
				t.Error(err)
			}
		}
	}()
	mailer, err := NewSMTPMailer(listener.Addr().String(), "signup@example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = mailer.SendCode(ctx, "person@example.com", "12345678")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("stalled SMTP deadline: %v", err)
	}
	<-done
}
