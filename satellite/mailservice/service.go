// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information

package mailservice

import (
	"bytes"
	"context"
	"crypto/tls"
	htmltemplate "html/template"
	"path/filepath"
	"sync"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"

	"storj.io/common/context2"
	"storj.io/storj/private/post"

	gomail "gopkg.in/mail.v2"
)

// Config defines values needed by mailservice service.
type Config struct {
	SMTPServerAddress string `help:"smtp server address" default:"" testDefault:"smtp.mail.test:587"`
	TemplatePath      string `help:"path to email templates source" default:""`
	From              string `help:"sender email address" default:"" testDefault:"Labs <storj@mail.test>"`
	AuthType          string `help:"smtp authentication type" releaseDefault:"login" devDefault:"simulate"`
	Login             string `help:"plain/login auth user login" default:""`
	Password          string `help:"plain/login auth user password" default:""`
	RefreshToken      string `help:"refresh token used to retrieve new access token" default:""`
	ClientID          string `help:"oauth2 app's client id" default:""`
	ClientSecret      string `help:"oauth2 app's client secret" default:""`
	TokenURI          string `help:"uri which is used when retrieving new access token" default:""`
}

var (
	mon = monkit.Package()
)

// Sender sends emails.
//
// architecture: Service
type Sender interface {
	SendEmail(ctx context.Context, msg *post.Message) error
	FromAddress() post.Address
}

// Message defines mailservice template-backed message for SendRendered method.
type Message interface {
	Template() string
	Subject() string
}

// Service sends template-backed email messages through SMTP.
//
// architecture: Service
type Service struct {
	log    *zap.Logger
	Sender Sender

	html *htmltemplate.Template
	// TODO(yar): prepare plain text version
	// text *texttemplate.Template

	sending sync.WaitGroup
}

// New creates new service.
func New(log *zap.Logger, sender Sender, templatePath string) (*Service, error) {
	var err error
	service := &Service{log: log, Sender: sender}

	// TODO(yar): prepare plain text version
	// service.text, err = texttemplate.ParseGlob(filepath.Join(templatePath, "*.txt"))
	// if err != nil {
	// 	return nil, err
	// }

	service.html, err = htmltemplate.ParseGlob(filepath.Join(templatePath, "*.html"))
	if err != nil {
		return nil, err
	}

	return service, nil
}

// Close closes and waits for any pending actions.
func (service *Service) Close() error {
	service.sending.Wait()
	return nil
}

// Send is generalized method for sending custom email message.
func (service *Service) Send(ctx context.Context, msg *post.Message) (err error) {
	defer mon.Task()(&ctx)(&err)
	return service.Sender.SendEmail(ctx, msg)
}

// SendRenderedAsync renders content from htmltemplate and texttemplate templates then sends it asynchronously.
func (service *Service) SendRenderedAsync(ctx context.Context, to []post.Address, msg Message) {
	// TODO: think of a better solution
	service.sending.Add(1)
	go func() {
		defer service.sending.Done()

		ctx, cancel := context.WithTimeout(context2.WithoutCancellation(ctx), 5*time.Second)
		defer cancel()

		err := service.SendRendered(ctx, to, msg)

		var recipients []string
		for _, recipient := range to {
			recipients = append(recipients, recipient.String())
		}

		if err != nil {
			service.log.Error("fail sending email",
				zap.Strings("recipients", recipients),
				zap.Error(err))
		} else {
			service.log.Info("email sent successfully",
				zap.Strings("recipients", recipients))
		}
	}()
}

// SendRendered renders content from htmltemplate and texttemplate templates then sends it.
func (service *Service) SendRendered(ctx context.Context, to []post.Address, msg Message) (err error) {
	defer mon.Task()(&ctx)(&err)

	var htmlBuffer bytes.Buffer
	//var textBuffer bytes.Buffer

	// TODO(yar): prepare plain text version
	// if err = service.text.ExecuteTemplate(&textBuffer, msg.Template() + ".txt", msg); err != nil {
	// 	return
	// }

	if err = service.html.ExecuteTemplate(&htmlBuffer, msg.Template()+".html", msg); err != nil {
		return
	}
	/*
		m := &post.Message{
			From:      service.Sender.FromAddress(),
			To:        to,
			Subject:   msg.Subject(),
			PlainText: textBuffer.String(),
			Parts: []post.Part{
				{
					Type:    "text/html; charset=UTF-8",
					Content: htmlBuffer.String(),
				},
			},
		}
	*/
	m := gomail.NewMessage()

	// Set E-Mail sender
	m.SetHeader("From", service.Sender.FromAddress().Address)

	// Set E-Mail receivers
	for _, to := range to {
		m.SetHeader("To", to.Address)
	}

	// Set E-Mail subject
	m.SetHeader("Subject", msg.Subject())

	// Set E-Mail body. You can set plain text or html with text/html
	m.SetBody("text/html", htmlBuffer.String())
	//host, port, _ := net.SplitHostPort(service.Sender.ServerAddress)
	// Settings for SMTP server
	d := gomail.NewDialer("mail.storx.io", 587, service.Sender.FromAddress().Address, "TEsSt@7865!")

	// This is only needed when SSL/TLS certificate is not valid on server.
	// In production this should be set to false.
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	service.log.Error("TLS Config Added")
	// Now send E-Mail
	if err = d.DialAndSend(m); err != nil {
		service.log.Error(err.Error())
		//panic(err)
		return
	}
	return
	//return service.Sender.SendEmail(ctx, m)
}
