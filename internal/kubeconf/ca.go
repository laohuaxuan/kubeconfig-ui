package kubeconf

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// ParseCANotAfter 解析集群 CA（base64 PEM/DER）的过期时间。
func ParseCANotAfter(caBase64 string) (time.Time, error) {
	raw := strings.TrimSpace(caBase64)
	if raw == "" {
		return time.Time{}, fmt.Errorf("CA certificate is empty")
	}
	derOrPem, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		derOrPem, err = base64.RawStdEncoding.DecodeString(raw)
		if err != nil {
			return time.Time{}, fmt.Errorf("decode CA certificate failed: %w", err)
		}
	}

	var cert *x509.Certificate
	if block, _ := pem.Decode(derOrPem); block != nil {
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse CA PEM failed: %w", err)
		}
	} else {
		cert, err = x509.ParseCertificate(derOrPem)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse CA certificate failed: %w", err)
		}
	}
	if cert.NotAfter.IsZero() {
		return time.Time{}, fmt.Errorf("CA certificate has empty NotAfter")
	}
	return cert.NotAfter.UTC(), nil
}

// SecondsUntilCAExpiry 返回距离 CA 过期的秒数（至少保留 1 小时缓冲校验由调用方决定）。
func SecondsUntilCAExpiry(caBase64 string) (int64, time.Time, error) {
	notAfter, err := ParseCANotAfter(caBase64)
	if err != nil {
		return 0, time.Time{}, err
	}
	sec := int64(time.Until(notAfter).Seconds())
	if sec <= 0 {
		return 0, notAfter, fmt.Errorf("集群 CA 证书已过期（%s）", notAfter.Format(time.RFC3339))
	}
	return sec, notAfter, nil
}
