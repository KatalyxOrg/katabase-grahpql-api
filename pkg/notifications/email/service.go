package email

import (
	"bytes"
	"fmt"
	"text/template"

	"gopkg.in/gomail.v2"
)

type emailService struct {
	TemplatesPath string
	Credentials   Credentials
}

func NewEmailService(templatesPath string, credentials Credentials) EmailService {
	return &emailService{
		TemplatesPath: templatesPath,
		Credentials:   credentials,
	}
}

func (s *emailService) Send(to string, subject string, templateName string, data interface{}, attachments ...string) error {
	m := gomail.NewMessage()

	m.SetHeader("From", fmt.Sprintf("\"Hello Workspace\" <%s>", s.Credentials.Email))
	m.SetHeader("To", to)
	m.SetHeader("Reply-To", s.Credentials.Email)
	m.SetHeader("Subject", subject)

	t, _ := template.ParseFiles(s.TemplatesPath + "/" + templateName + ".html")
	var body bytes.Buffer

	body.Write([]byte(""))

	t.Execute(&body, data)

	m.SetBody("text/html", body.String())

	// Add attachments if any
	for _, attachment := range attachments {
		m.Attach(attachment)
	}

	d := gomail.NewDialer(s.Credentials.Host, s.Credentials.Port, s.Credentials.Email, s.Credentials.Password)
	// Send the email
	if err := d.DialAndSend(m); err != nil {
		return err
	}

	return nil
}
