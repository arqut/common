package mailer

import (
	"crypto/tls"
	"strconv"
	"strings"

	"github.com/arqut/common/system"
	"github.com/arqut/common/utils"
	"gopkg.in/gomail.v2"
)

var (
	dialer        *gomail.Dialer
	Supporter     string
	DefaultSender string
)

func Init() {
	Supporter = system.Env("MAILER_SUPPORTER", "Tuan Phan <peter.phan07@gmail.com>")
	DefaultSender = system.Env("MAILER_SENDER", "Arqut <info@semilimes.com>")
	port, _ := strconv.Atoi(system.Env("SMTP_PORT"))
	dialer := gomail.NewDialer(system.Env("SMTP_HOST"), port, system.Env("SMTP_USER"), system.Env("SMTP_PASS"))
	dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true}
}

func Send(to string, subject string, message string, isText ...bool) error {
	m := gomail.NewMessage()
	m.SetHeader("subject", subject)
	m.SetHeader("From", DefaultSender)
	m.SetHeader("To", to)

	if len(isText) > 0 && isText[0] {
		m.SetBody("text/html", message)
		m.SetBody("text/html", strings.ReplaceAll(message, "\n", "<br>"))
	} else {
		m.SetBody("text/html", utils.StripHtmlTags(message))
		m.SetBody("text/html", message)
	}

	// send the email
	return dialer.DialAndSend(m)
}

func NotifySupport(subject string, message interface{}) error {
	htmlMesasge := "<pre>\n" + utils.ToString(message) + "</pre>"
	return Send(Supporter, subject, htmlMesasge)
}
