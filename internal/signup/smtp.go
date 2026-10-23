package signup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"time"
)

type SMTPMailer struct {
	Addr, From, Username, Password string
	// nil uses system trust. Tests supply a private CA without disabling TLS verification.
	roots *x509.CertPool
}

func NewSMTPMailer(addr, from, user, password string) (*SMTPMailer, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, errors.New("signup: SMTP host:port is required")
	}
	normalized, err := NormalizeEmail(from)
	if err != nil {
		return nil, errors.New("signup: valid SMTP from address is required")
	}
	if (user == "") != (password == "") {
		return nil, errors.New("signup: SMTP username and password must be configured together")
	}
	return &SMTPMailer{Addr: addr, From: normalized, Username: user, Password: password}, nil
}
func (m *SMTPMailer) SendCode(ctx context.Context, to, code string) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	host, _, err := net.SplitHostPort(m.Addr)
	if err != nil {
		return err
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", m.Addr)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	deadline := time.Now().Add(8 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	if err = client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: m.roots}); err != nil {
		return err
	}
	if m.Username != "" {
		if err = client.Auth(smtp.PlainAuth("", m.Username, m.Password, host)); err != nil {
			return err
		}
	}
	if err = client.Mail(m.From); err != nil {
		return err
	}
	if err = client.Rcpt(to); err != nil {
		return err
	}
	body, err := client.Data()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(body, "From: Harbor <%s>\r\nTo: %s\r\nSubject: Verify your Harbor email\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour Harbor signup code is: %s\r\n\r\nEnter this code in the browser where you started signup. It expires in 10 minutes.\r\nThis code cannot sign in to or recover an existing account.\r\nIf you did not request this, ignore this email.\r\n", m.From, to, code)
	if err != nil {
		return err
	}
	if err = body.Close(); err != nil {
		return err
	}
	return client.Quit()
}
