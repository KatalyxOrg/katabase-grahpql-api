package email

//go:generate mockgen -source=types.go -destination=../../mocks/mock_emailservice.go -package=mocks

// Templates

// Service

type Credentials struct {
	Host     string
	Port     int
	Email    string
	Password string
}

type EmailService interface {
	Send(to string, subject string, templateName string, data interface{}, attachments ...string) error
}
