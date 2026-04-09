package notifier

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/cert-watcher/cert-watcher/internal/checker"
)

// EmailNotifier sends notifications via SMTP email.
type EmailNotifier struct {
	host         string
	port         int
	user         string
	password     string
	from         string
	to           []string
	subjectPrefix string
}

// NewEmailNotifier creates a new email notifier.
func NewEmailNotifier(host string, port int, user, password, from string, to []string, subjectPrefix string) *EmailNotifier {
	return &EmailNotifier{
		host:         host,
		port:         port,
		user:         user,
		password:     password,
		from:         from,
		to:           to,
		subjectPrefix: subjectPrefix,
	}
}

// Name returns the name of this notifier.
func (e *EmailNotifier) Name() string {
	return "email"
}

// Send sends an email notification.
func (e *EmailNotifier) Send(level AlertLevel, certInfo *checker.CertInfo) error {
	subject := fmt.Sprintf("%s Certificate Alert: %s", e.subjectPrefix, certInfo.Host)
	if level == LevelCritical {
		subject = fmt.Sprintf("%s CRITICAL: %s", e.subjectPrefix, certInfo.Host)
	}

	body := FormatEmailBody(level, certInfo)

	msg := buildEmailMessage(e.from, e.to, subject, body)

	return e.sendMail(msg)
}

// buildEmailMessage constructs a RFC 5322 compliant email message.
func buildEmailMessage(from string, to []string, subject, body string) string {
	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = strings.Join(to, ", ")
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/plain; charset=\"utf-8\""
	headers["Content-Transfer-Encoding"] = "quoted-printable"

	var msg strings.Builder
	for k, v := range headers {
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)

	return msg.String()
}

// sendMail sends an email using SMTP.
func (e *EmailNotifier) sendMail(msg string) error {
	addr := fmt.Sprintf("%s:%d", e.host, e.port)

	// Set up TLS config
	tlsConfig := &tls.Config{
		ServerName: e.host,
		MinVersion: tls.VersionTLS12,
	}

	// Connect to the SMTP server
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		// Try without TLS for port 25
		if e.port != 25 {
			return fmt.Errorf("failed to connect to SMTP: %w", err)
		}
		conn, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP: %w", err)
		}
	}
	defer conn.Close()

	// Authenticate if credentials are provided
	if e.user != "" && e.password != "" {
		auth := smtp.PlainAuth("", e.user, e.password, e.host)
		if err := conn.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	// Set sender and recipients
	if err := conn.Mail(e.from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	for _, to := range e.to {
		if err := conn.Rcpt(to); err != nil {
			return fmt.Errorf("failed to set recipient: %w", err)
		}
	}

	// Send the message body
	w, err := conn.Data()
	if err != nil {
		return fmt.Errorf("failed to open data writer: %w", err)
	}
	_, err = w.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	return conn.Quit()
}

// FormatEmailBody creates the HTML body for an email notification.
func FormatEmailBody(level AlertLevel, certInfo *checker.CertInfo) string {
	emoji := "⚠️"
	color := "#ffa500" // orange
	if level == LevelCritical {
		emoji = "🚨"
		color = "#ff0000" // red
	}

	return fmt.Sprintf(`%s TLS Certificate Alert

==============================================
Host: %s
==============================================

Status: %s
Days Remaining: %d days
Expires: %s (UTC)
Issued: %s (UTC)

Certificate Details:
------------------
Subject: %s
Issuer: %s
Serial: %s

==============================================
This is an automated alert from Cert-Watcher.
Please take action to renew the certificate.
==============================================
`,
		emoji,
		certInfo.Host,
		level,
		certInfo.DaysRemaining,
		certInfo.NotAfter.UTC().Format("2006-01-02 15:04:05"),
		certInfo.NotBefore.UTC().Format("2006-01-02 15:04:05"),
		certInfo.Subject,
		certInfo.Issuer,
		certInfo.Serial,
	)
}
