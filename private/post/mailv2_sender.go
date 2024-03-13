package post

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"

	gomail "gopkg.in/mail.v2"
)

type MailV2 struct {
	ServerAddress string

	From Address
	Auth LoginAuth
}

func (m *MailV2) FromAddress() Address {
	return m.From
}

func (m *MailV2) SendEmail(ctx context.Context, msg *Message) (err error) {
	g := gomail.NewMessage()

	// Set E-Mail sender
	g.SetHeader("From", m.FromAddress().Address)

	// Set E-Mail receivers
	for _, to := range msg.To {
		g.SetHeader("To", to.Address)
	}

	// Set E-Mail subject
	g.SetHeader("Subject", msg.Subject)

	// Set E-Mail body. You can set plain text or html with text/html
	if len(msg.Parts) == 0 {
		return nil
	}
	part := msg.Parts[0]

	g.SetBody(part.Type, part.Content)
	host, port, _ := net.SplitHostPort(m.ServerAddress)
	p, err := strconv.Atoi(port)
	if err != nil {
		return err
	}

	// Settings for SMTP server
	d := gomail.NewDialer(host, p, m.Auth.Username, m.Auth.Password)

	// This is only needed when SSL/TLS certificate is not valid on server.
	// In production this should be set to false.
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	// Now send E-Mail
	return d.DialAndSend(g)
}
