package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"kubeconfig-ui/internal/store"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	JWTSecret   string
	TokenExpiry time.Duration
	SMTPHost    string
	SMTPPort    int
	SMTPUser    string
	SMTPPass    string
	SMTPFrom    string
}

type Auth struct {
	store       *store.Store
	cfg         Config
	smtpHost    string
	smtpPort    int
	smtpUser    string
	smtpPass    string
	smtpFrom    string
}

type Claims struct {
	UserID   int64      `json:"user_id"`
	Username string     `json:"username"`
	Role     store.Role `json:"role"`
	jwt.RegisteredClaims
}

var (
	ErrSMTPConfigInvalid = errors.New("smtp config invalid")
	ErrSMTPConnect       = errors.New("smtp connect failed")
	ErrSMTPAuth          = errors.New("smtp auth failed")
	ErrSMTPRecipient     = errors.New("smtp recipient rejected")
	ErrSMTPSend          = errors.New("smtp send failed")
)

func New(s *store.Store, cfg Config) *Auth {
	return &Auth{
		store:       s,
		cfg:         cfg,
		smtpHost:    cfg.SMTPHost,
		smtpPort:    cfg.SMTPPort,
		smtpUser:    cfg.SMTPUser,
		smtpPass:    cfg.SMTPPass,
		smtpFrom:    cfg.SMTPFrom,
	}
}

func (a *Auth) HashPassword(password string) (string, error) {
	raw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (a *Auth) ComparePassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (a *Auth) GenerateToken(user *store.User) (string, error) {
	claims := Claims{
		UserID:   user.ID,
		Username: user.Name,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(a.cfg.TokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(a.cfg.JWTSecret))
}

func (a *Auth) ParseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

func (a *Auth) GenerateResetToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *Auth) SendPasswordResetEmail(to, resetURL string, ttl time.Duration) error {
	return a.sendMail(
		to,
		"Kubeconfig管理系统密码重置通知",
		fmt.Sprintf(
			"您好，\n\n我们收到了您的密码重置请求。请点击下面的链接设置新密码：\n%s\n\n该链接将在 %d 分钟后失效，且只能使用一次。\n如果这不是您的操作，请忽略本邮件并尽快检查账号安全。\n",
			resetURL,
			int(ttl.Minutes()),
		),
	)
}

func (a *Auth) SendPasswordChangedEmail(to, ip, device string, changedAt time.Time) error {
	return a.sendMail(
		to,
		"Kubeconfig管理系统密码重置成功通知",
		fmt.Sprintf(
			"您好，\n\n您的账号密码已于 %s 修改成功。\n登录 IP：%s\n设备信息：%s\n\n如果这不是您的操作，请立即联系管理员。\n",
			changedAt.Format("2006-01-02 15:04:05"),
			ip,
			device,
		),
	)
}

func (a *Auth) sendMail(to, subject, body string) error {
	if a.smtpHost == "" || a.smtpPort == 0 || a.smtpFrom == "" {
		return fmt.Errorf("%w: smtp_host/smtp_port/smtp_from required", ErrSMTPConfigInvalid)
	}

	headers := map[string]string{
		"From":         a.smtpFrom,
		"To":           to,
		"Subject":      subject,
		"MIME-Version": "1.0",
		"Content-Type": "text/plain; charset=UTF-8",
	}

	var msg bytes.Buffer
	for k, v := range headers {
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)

	addr := fmt.Sprintf("%s:%d", a.smtpHost, a.smtpPort)
	if a.smtpPort == 465 {
		return a.sendMailWithTLS(addr, to, msg.Bytes())
	}

	var auth smtp.Auth
	if a.smtpUser != "" && a.smtpPass != "" {
		auth = smtp.PlainAuth("", a.smtpUser, a.smtpPass, a.smtpHost)
	}
	if err := smtp.SendMail(addr, auth, a.smtpFrom, []string{to}, msg.Bytes()); err != nil {
		return wrapSMTPError(err)
	}
	return nil
}

func (a *Auth) sendMailWithTLS(addr, to string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: a.smtpHost})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSMTPConnect, err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, a.smtpHost)
	if err != nil {
		return err
	}
	defer client.Close()

	if a.smtpUser != "" && a.smtpPass != "" {
		auth := smtp.PlainAuth("", a.smtpUser, a.smtpPass, a.smtpHost)
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return wrapSMTPError(err)
			}
		}
	}

	if err := client.Mail(a.smtpFrom); err != nil {
		return wrapSMTPError(err)
	}
	if err := client.Rcpt(to); err != nil {
		return wrapSMTPError(err)
	}

	wc, err := client.Data()
	if err != nil {
		return wrapSMTPError(err)
	}
	if _, err := wc.Write(msg); err != nil {
		return wrapSMTPError(err)
	}
	if err := wc.Close(); err != nil {
		return wrapSMTPError(err)
	}
	return client.Quit()
}

func wrapSMTPError(err error) error {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "535"), strings.Contains(msg, "authentication failed"), strings.Contains(msg, "auth"):
		return fmt.Errorf("%w: %v", ErrSMTPAuth, err)
	case strings.Contains(msg, "550"), strings.Contains(msg, "553"), strings.Contains(msg, "rcpt"), strings.Contains(msg, "recipient"):
		return fmt.Errorf("%w: %v", ErrSMTPRecipient, err)
	case strings.Contains(msg, "connect"), strings.Contains(msg, "dial"), strings.Contains(msg, "timeout"), strings.Contains(msg, "refused"):
		return fmt.Errorf("%w: %v", ErrSMTPConnect, err)
	default:
		return fmt.Errorf("%w: %v", ErrSMTPSend, err)
	}
}
