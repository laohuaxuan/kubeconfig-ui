package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"kubeconfig-ui/internal/auth"
	"kubeconfig-ui/internal/k8sclient"
	"kubeconfig-ui/internal/kubeconf"
	"kubeconfig-ui/internal/store"

	"github.com/gin-gonic/gin"
)

var numericRegex = regexp.MustCompile(`^\d+$`)
var hasUppercaseRegex = regexp.MustCompile(`[A-Z]`)
var hasLowercaseRegex = regexp.MustCompile(`[a-z]`)
var hasDigitRegex = regexp.MustCompile(`[0-9]`)
var hasSpecialRegex = regexp.MustCompile(`[^A-Za-z0-9]`)
var usernameRegex = regexp.MustCompile(`^[a-z0-9]+$`)
var phoneRegex = regexp.MustCompile(`^1[3-9]\d{9}$`)
var emailRegex = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

const passwordRuleError = "密码不符合规范（需包含大小写字母、数字、特殊字符，不少于6位且不超过24位）"

func isNumeric(s string) bool {
	return numericRegex.MatchString(s)
}

func isPasswordValid(password string) bool {
	if len(password) < 6 || len(password) > 24 {
		return false
	}
	return hasUppercaseRegex.MatchString(password) &&
		hasLowercaseRegex.MatchString(password) &&
		hasDigitRegex.MatchString(password) &&
		hasSpecialRegex.MatchString(password)
}

func pickCharset(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}

func generateRandomPassword(length int) (string, error) {
	if length < 6 {
		length = 8
	}
	if length > 24 {
		length = 24
	}
	const (
		upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lower   = "abcdefghijklmnopqrstuvwxyz"
		digits  = "0123456789"
		special = "!@#$%^&*"
	)
	all := upper + lower + digits + special
	b := make([]byte, length)
	var err error
	if b[0], err = pickCharset(upper); err != nil {
		return "", err
	}
	if b[1], err = pickCharset(lower); err != nil {
		return "", err
	}
	if b[2], err = pickCharset(digits); err != nil {
		return "", err
	}
	if b[3], err = pickCharset(special); err != nil {
		return "", err
	}
	for i := 4; i < length; i++ {
		if b[i], err = pickCharset(all); err != nil {
			return "", err
		}
	}
	for i := len(b) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		j := int(jBig.Int64())
		b[i], b[j] = b[j], b[i]
	}
	pwd := string(b)
	if !isPasswordValid(pwd) {
		return generateRandomPassword(length)
	}
	return pwd, nil
}

func buildResetPasswordURL(c *gin.Context, token string) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	if proto := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); proto != "" {
		scheme = strings.ToLower(strings.Split(proto, ",")[0])
	}
	host := c.Request.Host
	if host == "" {
		host = "localhost:8080"
	}
	return fmt.Sprintf("%s://%s/reset-password?token=%s", scheme, host, url.QueryEscape(token))
}

type Handler struct {
	store *store.Store
	auth  *auth.Auth
}

type registerRequest struct {
	Username     string `json:"username"`
	DisplayName  string `json:"display_name"`
	Phone        string `json:"phone"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	CaptchaToken string `json:"captcha_token"`
	CaptchaCode  string `json:"captcha_code"`
}

type loginRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	CaptchaToken string `json:"captcha_token"`
	CaptchaCode  string `json:"captcha_code"`
}

type resetPasswordRequest struct {
	Account string `json:"account"`
}

type changePasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type createAccountRequest struct {
	Name            string `json:"name"`
	AccountCode     string `json:"account_code"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	Region          string `json:"region"`
}

type createClusterRequest struct {
	AccountID       uint   `json:"account_id"`
	Name            string `json:"name"`
	ClusterID       string `json:"cluster_id"`
	Version         string `json:"version"`
	Provider        string `json:"provider"`
	APIServer       string `json:"api_server"`
	CACert          string `json:"ca_cert"`
	UploadedContent string `json:"uploaded_kubeconfig"`
}

type permissionRuleRequest struct {
	APIGroup string   `json:"api_group"`
	Resource string   `json:"resource"`
	Verbs    []string `json:"verbs"`
}

type createKubeconfigRequest struct {
	Name               string                  `json:"name"`
	AccountID          uint                    `json:"account_id"`
	ClusterID          uint                    `json:"cluster_id"`
	ServiceAccountName string                  `json:"service_account_name"`
	SANamespace        string                  `json:"sa_namespace"`
	RoleNamespace      string                  `json:"role_namespace"`
	RoleKind           string                  `json:"role_kind"`
	Rules              []permissionRuleRequest `json:"rules"`
	// TokenTTLMode: temporary | custom | long
	TokenTTLMode string `json:"token_ttl_mode"`
	// TokenTTLDays used when token_ttl_mode=custom
	TokenTTLDays int `json:"token_ttl_days"`
	// Deprecated fields kept for backward compatibility parsing only.
	Namespace string   `json:"namespace"`
	Token     string   `json:"token"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

// remainingTokenDays 返回距离 Token 过期的剩余整天数（向上取整）；无过期信息返回 nil；已过期返回 0。
func remainingTokenDays(expiresAt *time.Time) any {
	if expiresAt == nil || expiresAt.IsZero() {
		return nil
	}
	sec := time.Until(*expiresAt).Seconds()
	if sec <= 0 {
		return 0
	}
	return int(math.Ceil(sec / 86400))
}

func resolveTokenTTL(mode string, days int, caCert string) (resolvedMode string, expirationSeconds int64, expiresAt time.Time, allowSecretFallback bool, err error) {
	resolvedMode = strings.ToLower(strings.TrimSpace(mode))
	if resolvedMode == "" {
		resolvedMode = "temporary"
	}
	caSeconds, caNotAfter, caErr := kubeconf.SecondsUntilCAExpiry(caCert)

	switch resolvedMode {
	case "temporary":
		expirationSeconds = 3 * 24 * 3600
		expiresAt = time.Now().UTC().Add(3 * 24 * time.Hour)
		if caErr == nil && expirationSeconds > caSeconds {
			return "", 0, time.Time{}, false, fmt.Errorf("临时有效期（3天）超过集群 CA 剩余有效期（至 %s）", caNotAfter.Format("2006-01-02"))
		}
		return resolvedMode, expirationSeconds, expiresAt, false, nil
	case "custom":
		if days < 1 {
			return "", 0, time.Time{}, false, fmt.Errorf("指定有效期天数必须为大于等于 1 的整数")
		}
		if days > 3650 {
			return "", 0, time.Time{}, false, fmt.Errorf("指定有效期天数不能超过 3650 天")
		}
		expirationSeconds = int64(days) * 24 * 3600
		expiresAt = time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)
		if caErr == nil && expirationSeconds > caSeconds {
			maxDays := caSeconds / (24 * 3600)
			if maxDays < 1 {
				return "", 0, time.Time{}, false, fmt.Errorf("集群 CA 即将过期，无法签发指定有效期 token")
			}
			return "", 0, time.Time{}, false, fmt.Errorf("指定有效期不能超过集群 CA 剩余天数（最多 %d 天，至 %s）", maxDays, caNotAfter.Format("2006-01-02"))
		}
		return resolvedMode, expirationSeconds, expiresAt, false, nil
	case "long":
		if caErr != nil {
			return "", 0, time.Time{}, false, fmt.Errorf("长期有效需要解析集群 CA: %v", caErr)
		}
		if caSeconds < 3600 {
			return "", 0, time.Time{}, false, fmt.Errorf("集群 CA 剩余有效期不足 1 小时，无法签发长期 token")
		}
		// 长期：与 CA 期限对齐；若集群 TokenRequest 上限不足则允许 Secret 回退
		return resolvedMode, caSeconds, caNotAfter, true, nil
	default:
		return "", 0, time.Time{}, false, fmt.Errorf("token_ttl_mode 必须是 temporary、custom 或 long")
	}
}

type createUserRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Phone       string `json:"phone"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

type updateRoleRequest struct {
	Role string `json:"role"`
}

type updateStatusRequest struct {
	Status string `json:"status"`
}

type resetUserPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

type updateProfileRequest struct {
	DisplayName     string `json:"display_name"`
	Phone           string `json:"phone"`
	Email           string `json:"email"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

type updateUserRequest struct {
	DisplayName string `json:"display_name"`
	Phone       string `json:"phone"`
	Email       string `json:"email"`
	Role        string `json:"role"`
}

func NewHandler(s *store.Store, a *auth.Auth) *Handler {
	return &Handler{store: s, auth: a}
}

func (h *Handler) RegisterRoutes(r *gin.Engine) {
	r.Use(cors())
	r.GET("/api/health", h.health)
	r.GET("/api/captcha", h.captchaImage)
	r.GET("/api/check-exists", h.checkExists)
	r.POST("/api/register", h.register)
	r.POST("/api/login", h.login)
	r.POST("/api/reset-password", h.requestResetPassword)
	r.POST("/api/change-password", h.changePassword)

	api := r.Group("/api")
	api.Use(h.requireAuth())
	{
		api.GET("/user-info", h.userInfo)
		api.PUT("/user-profile", h.updateOwnProfile)
		api.POST("/logout", h.logout)
		api.GET("/accounts", h.listAccounts)
		api.GET("/clusters", h.listClusters)
		api.GET("/kubeconfigs", h.listKubeconfigs)
		api.GET("/kubeconfigs/:id/rbac-yaml", h.getRBACYaml)

		api.GET("/kubeconfigs/:id/download", h.requireDownloadKubeconfig(), h.downloadKubeconfig)
		api.GET("/clusters/:id/namespaces", h.requireCreateKubeconfig(), h.listClusterNamespaces)
		api.POST("/kubeconfigs", h.requireCreateKubeconfig(), h.createKubeconfig)

		api.GET("/audit-logs", h.requireViewAudit(), h.auditLogs)
		api.POST("/accounts", h.requireManageDatasource(), h.createAccount)
		api.PUT("/accounts/:id", h.requireManageDatasource(), h.updateAccount)
		api.DELETE("/accounts/:id", h.requireManageDatasource(), h.deleteAccount)
		api.POST("/clusters", h.requireManageDatasource(), h.createCluster)
		api.PUT("/clusters/:id", h.requireManageDatasource(), h.updateCluster)
		api.DELETE("/clusters/:id", h.requireManageDatasource(), h.deleteCluster)
		api.DELETE("/kubeconfigs/:id", h.requireDeleteKubeconfig(), h.deleteKubeconfig)

		api.GET("/users", h.requireManageUsers(), h.listUsers)
		api.POST("/users", h.requireCreateUsers(), h.createUser)
		api.PUT("/users/:id", h.requireManageUsers(), h.updateUser)
		api.PUT("/users/:id/role", h.requireManageUsers(), h.updateUserRole)
		api.PUT("/users/:id/status", h.requireManageUsers(), h.updateUserStatus)
		api.PUT("/users/:id/reset-password", h.requireManageUsers(), h.resetUserPassword)
		api.DELETE("/users/:id", h.requireManageUsers(), h.deleteUser)
	}
}

func (h *Handler) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	req.Phone = strings.TrimSpace(req.Phone)
	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)
	req.CaptchaToken = strings.TrimSpace(req.CaptchaToken)
	req.CaptchaCode = strings.TrimSpace(req.CaptchaCode)

	if req.CaptchaToken == "" || req.CaptchaCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "captcha token and code are required"})
		return
	}
	if len(req.CaptchaCode) != 4 || !isNumeric(req.CaptchaCode) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "captcha code must be 4 digits"})
		return
	}
	if !h.verifyCaptcha(req.CaptchaToken, req.CaptchaCode) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired captcha"})
		return
	}
	if req.Username == "" || req.DisplayName == "" || req.Phone == "" || req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username, display_name, phone, email, password are required"})
		return
	}
	if len(req.DisplayName) > 120 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "display_name must be at most 120 characters"})
		return
	}
	if len(req.Username) < 3 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username must be at least 3 characters"})
		return
	}
	if len(req.Username) > 24 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username must be at most 24 characters"})
		return
	}
	adminBlacklist := []string{"root", "admin", "administrator", "superadmin", "super_admin", "admin_root", "root_admin", "system", "adminstrator"}
	lowerUsername := strings.ToLower(req.Username)
	for _, name := range adminBlacklist {
		if lowerUsername == name {
			c.JSON(http.StatusBadRequest, gin.H{"error": "该用户名不允许注册"})
			return
		}
	}
	if !usernameRegex.MatchString(req.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username must contain only lowercase letters and digits"})
		return
	}
	if !phoneRegex.MatchString(req.Phone) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid phone number"})
		return
	}
	if !emailRegex.MatchString(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email"})
		return
	}
	if !isPasswordValid(req.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": passwordRuleError})
		return
	}
	if _, err := h.store.GetUserByName(req.Username); err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username already exists"})
		return
	}
	if _, err := h.store.GetUserByPhone(req.Phone); err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "phone already registered"})
		return
	}
	if _, err := h.store.GetUserByEmail(req.Email); err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email already registered"})
		return
	}
	hash, err := h.auth.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash password failed"})
		return
	}
	user := &store.User{
		Name:         req.Username,
		DisplayName:  req.DisplayName,
		Phone:        req.Phone,
		Email:        req.Email,
		PasswordHash: hash,
		Role:         store.RoleWatcher,
		Status:       "active",
	}
	if err := h.store.CreateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_ = h.store.WriteAudit(&store.AuditLog{
		UserID:      user.ID,
		Username:    user.Name,
		DisplayName: user.DisplayName,
		Action:      "register",
		Result:      "success",
		IP:          c.ClientIP(),
		Detail:      "user registered",
	})
	c.JSON(http.StatusOK, gin.H{"message": "registered"})
}

func (h *Handler) login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)
	req.CaptchaToken = strings.TrimSpace(req.CaptchaToken)
	req.CaptchaCode = strings.TrimSpace(req.CaptchaCode)
	if req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required"})
		return
	}
	if req.CaptchaToken == "" || req.CaptchaCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "captcha token and code are required"})
		return
	}
	if len(req.CaptchaCode) != 4 || !isNumeric(req.CaptchaCode) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "captcha code must be 4 digits"})
		return
	}
	if !h.verifyCaptcha(req.CaptchaToken, req.CaptchaCode) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired captcha"})
		return
	}

	var user *store.User
	var err error
	if len(req.Username) == 11 && isNumeric(req.Username) {
		user, err = h.store.GetUserByPhone(req.Username)
	} else {
		user, err = h.store.GetUserByName(req.Username)
	}
	if err != nil || !h.auth.ComparePassword(user.PasswordHash, req.Password) {
		_ = h.store.WriteAudit(&store.AuditLog{
			Username:    req.Username,
			DisplayName: req.Username,
			Action:      "login",
			Result:      "failed",
			IP:          c.ClientIP(),
			Detail:      "invalid credentials",
		})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	displayName := strings.TrimSpace(user.DisplayName)
	if displayName == "" {
		displayName = user.Name
	}
	if strings.ToLower(strings.TrimSpace(user.Status)) == "disabled" {
		_ = h.store.WriteAudit(&store.AuditLog{
			UserID:      user.ID,
			Username:    user.Name,
			DisplayName: displayName,
			Action:      "login",
			Result:      "failed",
			IP:          c.ClientIP(),
			Detail:      "user is disabled",
		})
		c.JSON(http.StatusForbidden, gin.H{"error": "user is disabled"})
		return
	}
	token, err := h.auth.GenerateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "generate token failed"})
		return
	}
	_ = h.store.WriteAudit(&store.AuditLog{
		UserID:      user.ID,
		Username:    user.Name,
		DisplayName: displayName,
		Action:      "login",
		Result:      "success",
		IP:          c.ClientIP(),
		Detail:      "login success",
	})
	c.JSON(http.StatusOK, gin.H{
		"token":        token,
		"user_id":      user.ID,
		"name":         user.Name,
		"display_name": displayName,
		"phone":        user.Phone,
		"email":        user.Email,
		"role":         string(user.Role),
	})
}

func (h *Handler) checkExists(c *gin.Context) {
	field := c.Query("field")
	value := c.Query("value")
	if field == "" || value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var err error
	switch field {
	case "username":
		_, err = h.store.GetUserByName(value)
	case "phone":
		_, err = h.store.GetUserByPhone(value)
	case "email":
		_, err = h.store.GetUserByEmail(value)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid field"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"exists": err == nil})
}

func (h *Handler) requestResetPassword(c *gin.Context) {
	var req resetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	account := strings.TrimSpace(req.Account)
	if account == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account is required"})
		return
	}

	var user *store.User
	var err error
	if len(account) == 11 && isNumeric(account) {
		user, err = h.store.GetUserByPhone(account)
	} else {
		user, err = h.store.GetUserByName(account)
	}
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "重置密码已发送到您的注册邮箱xxxx@xxx.xx"})
		return
	}

	expireDuration := 30 * time.Minute
	nowUnix := time.Now().Unix()
	// 仍有未使用且未过期的重置链接时，禁止重复发送；成功改密后链接已删除，可再次申请新链接
	if existing, err := h.store.GetResetTokenByUserID(user.ID); err == nil {
		if existing.ExpiresAt >= nowUnix {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "重置邮件已发送，30分钟内请勿重复点击，请查收邮箱"})
			return
		}
		_ = h.store.DeleteResetToken(user.ID)
	}

	if err := h.store.DeleteResetToken(user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send reset link"})
		return
	}

	token := h.auth.GenerateResetToken()
	if err := h.store.SaveResetToken(&store.ResetToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(expireDuration).Unix(),
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send reset link"})
		return
	}

	clientIP := c.ClientIP()
	clientDevice := c.Request.UserAgent()
	resetURL := buildResetPasswordURL(c, token)
	if err := h.auth.SendPasswordResetEmail(user.Email, resetURL, expireDuration); err != nil {
		_ = h.store.DeleteResetToken(user.ID)
		switch {
		case errors.Is(err, auth.ErrSMTPConfigInvalid):
			c.JSON(http.StatusInternalServerError, gin.H{"error": "mail service is not configured"})
		case errors.Is(err, auth.ErrSMTPConnect):
			c.JSON(http.StatusBadGateway, gin.H{"error": "mail service is unavailable"})
		case errors.Is(err, auth.ErrSMTPAuth):
			c.JSON(http.StatusBadGateway, gin.H{"error": "mail service authentication failed"})
		case errors.Is(err, auth.ErrSMTPRecipient):
			c.JSON(http.StatusBadRequest, gin.H{"error": "registered email is unavailable"})
		default:
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to send reset email"})
		}
		return
	}

	if err := h.store.CreatePasswordResetRequestLog(&store.PasswordResetRequestLog{
		UserID: user.ID,
		Email:  user.Email,
		IP:     clientIP,
		Device: clientDevice,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send reset link"})
		return
	}

	_ = h.store.WriteAudit(&store.AuditLog{
		UserID:      user.ID,
		Username:    user.Name,
		DisplayName: user.DisplayName,
		Action:      "reset_password_request",
		Result:      "success",
		IP:          clientIP,
		Detail:      "password reset link sent",
	})
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("重置密码已发送到您的注册邮箱%s", user.Email)})
}

func (h *Handler) changePassword(c *gin.Context) {
	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	req.NewPassword = strings.TrimSpace(req.NewPassword)
	if !isPasswordValid(req.NewPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"error": passwordRuleError})
		return
	}

	resetToken, err := h.store.GetResetToken(req.Token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该重置链接已失效或已使用，请重新发起忘记密码"})
		return
	}
	if time.Now().Unix() > resetToken.ExpiresAt {
		_ = h.store.DeleteResetToken(resetToken.UserID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "该重置链接已过期，请重新发起忘记密码"})
		return
	}

	user, err := h.store.GetUserByID(resetToken.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该重置链接已失效，请重新发起忘记密码"})
		return
	}
	if h.auth.ComparePassword(user.PasswordHash, req.NewPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "新密码不能与旧密码相同"})
		return
	}

	hash, err := h.auth.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password"})
		return
	}
	if err := h.store.UpdateUserPassword(resetToken.UserID, hash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password"})
		return
	}
	// 成功设置后立即失效该账号全部重置链接（一次性）
	if err := h.store.DeleteResetToken(resetToken.UserID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password"})
		return
	}

	clientIP := c.ClientIP()
	clientDevice := c.Request.UserAgent()
	_ = h.auth.SendPasswordChangedEmail(user.Email, clientIP, clientDevice, time.Now())
	_ = h.store.WriteAudit(&store.AuditLog{
		UserID:      user.ID,
		Username:    user.Name,
		DisplayName: user.DisplayName,
		Action:      "change_password",
		Result:      "success",
		IP:          clientIP,
		Detail:      "password changed via reset link",
	})
	c.JSON(http.StatusOK, gin.H{"message": "密码已重置成功，请返回登录"})
}

func (h *Handler) userInfo(c *gin.Context) {
	userID := c.GetInt64("user_id")
	displayName := c.GetString("username")
	if user, err := h.store.GetUserByID(userID); err == nil {
		if dn := strings.TrimSpace(user.DisplayName); dn != "" {
			displayName = dn
		} else {
			displayName = user.Name
		}
		c.JSON(http.StatusOK, gin.H{
			"user_id":      user.ID,
			"name":         user.Name,
			"display_name": displayName,
			"phone":        user.Phone,
			"email":        user.Email,
			"role":         string(user.Role),
			"status":       user.Status,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user_id":      userID,
		"name":         c.GetString("username"),
		"display_name": displayName,
		"role":         c.GetString("role"),
	})
}

func (h *Handler) updateOwnProfile(c *gin.Context) {
	var req updateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	phone := strings.TrimSpace(req.Phone)
	email := strings.TrimSpace(req.Email)
	newPassword := strings.TrimSpace(req.NewPassword)
	confirmPassword := strings.TrimSpace(req.ConfirmPassword)
	if displayName == "" || phone == "" || email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "display_name, phone, email are required"})
		return
	}
	userID := c.GetInt64("user_id")
	if userID <= 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user session"})
		return
	}
	user, err := h.store.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if newPassword != "" || confirmPassword != "" {
		if !isPasswordValid(newPassword) {
			c.JSON(http.StatusBadRequest, gin.H{"error": passwordRuleError})
			return
		}
		if newPassword != confirmPassword {
			c.JSON(http.StatusBadRequest, gin.H{"error": "两次输入的密码不一致"})
			return
		}
		if h.auth.ComparePassword(user.PasswordHash, newPassword) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "新密码不能与旧密码相同"})
			return
		}
	}
	if err := h.store.UpdateUserProfile(userID, displayName, phone, email); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if newPassword != "" {
		hash, err := h.auth.HashPassword(newPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "hash password failed"})
			return
		}
		if err := h.store.UpdateUserPassword(userID, hash); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		_ = h.store.WriteAudit(&store.AuditLog{
			UserID:      user.ID,
			Username:    user.Name,
			DisplayName: displayName,
			Action:      "change_password",
			Result:      "success",
			IP:          c.ClientIP(),
			Detail:      "password changed via profile",
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"message":      "updated",
		"display_name": displayName,
		"phone":        phone,
		"email":        email,
	})
}

func (h *Handler) auditLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	keyword := strings.TrimSpace(c.Query("keyword"))
	// Backward-compatible filters folded into keyword if provided separately.
	if keyword == "" {
		parts := []string{
			strings.TrimSpace(c.Query("username")),
			strings.TrimSpace(c.Query("action")),
			strings.TrimSpace(c.Query("result")),
		}
		for _, p := range parts {
			if p != "" {
				keyword = p
				break
			}
		}
	}
	startAt, err := parseQueryTime(c.Query("start_at"), false)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid start_at"})
		return
	}
	endAt, err := parseQueryTime(c.Query("end_at"), true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid end_at"})
		return
	}

	items, total, err := h.store.ListAuditLogs(page, size, keyword, startAt, endAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		displayName := strings.TrimSpace(item.DisplayName)
		if displayName == "" {
			displayName = item.Username
		}
		result = append(result, gin.H{
			"id":           item.ID,
			"created_at":   item.CreatedAt,
			"user_id":      item.UserID,
			"username":     item.Username,
			"display_name": displayName,
			"action":       item.Action,
			"result":       item.Result,
			"ip":           item.IP,
			"detail":       item.Detail,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"total": total,
		"items": result,
		"page":  page,
		"size":  size,
	})
}

func parseQueryTime(raw string, endOfDay bool) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	raw = strings.ReplaceAll(raw, "T", " ")
	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
	}
	var parsed time.Time
	var err error
	matchedDateOnly := false
	for _, layout := range layouts {
		parsed, err = time.ParseInLocation(layout, raw, time.Local)
		if err == nil {
			matchedDateOnly = layout == "2006-01-02"
			break
		}
	}
	if err != nil {
		return nil, err
	}
	if endOfDay && matchedDateOnly {
		parsed = parsed.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
	}
	return &parsed, nil
}

func (h *Handler) logout(c *gin.Context) {
	h.writeAudit(c, "logout", "success", "user logout")
	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

func (h *Handler) writeAudit(c *gin.Context, action, result, detail string) {
	userID := c.GetInt64("user_id")
	username := c.GetString("username")
	displayName := username
	if userID > 0 {
		if user, err := h.store.GetUserByID(userID); err == nil {
			if dn := strings.TrimSpace(user.DisplayName); dn != "" {
				displayName = dn
			} else {
				displayName = user.Name
			}
			if username == "" {
				username = user.Name
			}
		}
	}
	_ = h.store.WriteAudit(&store.AuditLog{
		UserID:      userID,
		Username:    username,
		DisplayName: displayName,
		Action:      action,
		Result:      result,
		IP:          c.ClientIP(),
		Detail:      detail,
	})
}

func (h *Handler) createAccount(c *gin.Context) {
	var req createAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	accountCode := strings.TrimSpace(req.AccountCode)
	if accountCode == "" {
		accountCode = name
	}
	region := strings.TrimSpace(req.Region)
	if region == "" {
		region = "-"
	}
	item := &store.AliyunAccount{
		Name:            name,
		AccountCode:     accountCode,
		AccessKeyID:     strings.TrimSpace(req.AccessKeyID),
		AccessKeySecret: strings.TrimSpace(req.AccessKeySecret),
		Region:          region,
	}
	if err := h.store.CreateAccount(item); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "created", "id": item.ID})
}

func (h *Handler) listAccounts(c *gin.Context) {
	items, err := h.store.ListAccounts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		result = append(result, gin.H{
			"id":            item.ID,
			"name":          item.Name,
			"account_code":  item.AccountCode,
			"access_key_id": item.AccessKeyID,
			"region":        item.Region,
		})
	}
	c.JSON(http.StatusOK, gin.H{"accounts": result})
}

func (h *Handler) updateAccount(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req createAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	item, err := h.store.GetAccountByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
		return
	}
	item.Name = name
	item.AccountCode = name
	if err := h.store.UpdateAccount(item); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated", "id": item.ID, "name": item.Name})
}

func (h *Handler) deleteAccount(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := h.store.DeleteAccount(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func generateClusterID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "cls-" + hex.EncodeToString(buf), nil
}

func (h *Handler) createCluster(c *gin.Context) {
	var req createClusterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	kubeconfigRaw := strings.TrimSpace(req.UploadedContent)
	if req.AccountID == 0 || strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Provider) == "" || kubeconfigRaw == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account_id, name, provider, uploaded_kubeconfig are required"})
		return
	}

	apiServer, caCert, err := kubeconf.ExtractClusterEndpoint(kubeconfigRaw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	clusterID, err := generateClusterID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "generate cluster_id failed"})
		return
	}

	item := &store.K8sCluster{
		AccountID:    req.AccountID,
		Name:         strings.TrimSpace(req.Name),
		ClusterID:    clusterID,
		Version:      strings.TrimSpace(req.Version),
		Provider:     strings.TrimSpace(req.Provider),
		APIServer:    apiServer,
		CACert:       caCert,
		KubeconfigIn: kubeconfigRaw,
	}
	if err := h.store.CreateCluster(item); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":    "created",
		"id":         item.ID,
		"cluster_id": item.ClusterID,
		"api_server": item.APIServer,
	})
}

func (h *Handler) listClusters(c *gin.Context) {
	accountIDRaw := strings.TrimSpace(c.Query("account_id"))
	var accountID uint
	if accountIDRaw != "" {
		id, err := strconv.ParseUint(accountIDRaw, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid account_id"})
			return
		}
		accountID = uint(id)
	}
	items, err := h.store.ListClusters(accountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		result = append(result, gin.H{
			"id":         item.ID,
			"account_id": item.AccountID,
			"name":       item.Name,
			"cluster_id": item.ClusterID,
			"version":    item.Version,
			"provider":   item.Provider,
			"api_server": item.APIServer,
		})
	}
	c.JSON(http.StatusOK, gin.H{"clusters": result})
}

func (h *Handler) updateCluster(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req createClusterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if req.AccountID == 0 || strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Provider) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account_id, name, provider are required"})
		return
	}
	item, err := h.store.GetClusterByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "cluster not found"})
		return
	}

	item.AccountID = req.AccountID
	item.Name = strings.TrimSpace(req.Name)
	item.Version = strings.TrimSpace(req.Version)
	item.Provider = strings.TrimSpace(req.Provider)

	kubeconfigRaw := strings.TrimSpace(req.UploadedContent)
	if kubeconfigRaw != "" {
		apiServer, caCert, parseErr := kubeconf.ExtractClusterEndpoint(kubeconfigRaw)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": parseErr.Error()})
			return
		}
		item.APIServer = apiServer
		item.CACert = caCert
		item.KubeconfigIn = kubeconfigRaw
	}

	if err := h.store.UpdateCluster(item); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":    "updated",
		"id":         item.ID,
		"cluster_id": item.ClusterID,
		"api_server": item.APIServer,
	})
}

func (h *Handler) deleteCluster(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := h.store.DeleteCluster(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (h *Handler) listClusterNamespaces(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	cluster, err := h.store.GetClusterByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "cluster not found"})
		return
	}
	names, err := k8sclient.ListNamespaces(cluster.KubeconfigIn)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"namespaces": names})
}

func (h *Handler) createKubeconfig(c *gin.Context) {
	var req createKubeconfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	saNamespace := strings.TrimSpace(req.SANamespace)
	if saNamespace == "" {
		saNamespace = strings.TrimSpace(req.Namespace)
	}
	roleNamespace := strings.TrimSpace(req.RoleNamespace)
	if strings.TrimSpace(req.Name) == "" || req.AccountID == 0 || req.ClusterID == 0 ||
		strings.TrimSpace(req.ServiceAccountName) == "" || saNamespace == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, account_id, cluster_id, service_account_name, sa_namespace are required"})
		return
	}
	roleKind := strings.TrimSpace(req.RoleKind)
	if roleKind == "" {
		roleKind = "Role"
	}
	if roleKind == "Role" && roleNamespace == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role_namespace is required when role_kind is Role"})
		return
	}
	rules := make([]kubeconf.PermissionRule, 0, len(req.Rules))
	for _, item := range req.Rules {
		rules = append(rules, kubeconf.PermissionRule{
			APIGroup: item.APIGroup,
			Resource: item.Resource,
			Verbs:    item.Verbs,
		})
	}
	// Backward compatibility: old clients sending flat resources/verbs.
	if len(rules) == 0 && len(req.Resources) > 0 {
		rules = append(rules, kubeconf.PermissionRule{
			APIGroup: "",
			Resource: strings.TrimSpace(req.Resources[0]),
			Verbs:    req.Verbs,
		})
		for _, resource := range req.Resources[1:] {
			rules = append(rules, kubeconf.PermissionRule{
				APIGroup: "",
				Resource: resource,
				Verbs:    req.Verbs,
			})
		}
	}

	cluster, err := h.store.GetClusterByID(req.ClusterID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster not found"})
		return
	}
	if cluster.AccountID != req.AccountID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster does not belong to selected account"})
		return
	}

	if strings.TrimSpace(cluster.KubeconfigIn) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster kubeconfig is empty, please re-add cluster with kubeconfig"})
		return
	}
	if strings.TrimSpace(cluster.ClusterID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_id is empty"})
		return
	}

	rbacYaml, err := kubeconf.BuildRBACYaml(req.ServiceAccountName, saNamespace, roleNamespace, roleKind, rules)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ttlMode, expirationSeconds, tokenExpiresAt, allowSecretFallback, err := resolveTokenTTL(req.TokenTTLMode, req.TokenTTLDays, cluster.CACert)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	saToken, err := k8sclient.ApplyRBACAndGetToken(
		cluster.KubeconfigIn,
		req.ServiceAccountName,
		saNamespace,
		roleNamespace,
		roleKind,
		rules,
		expirationSeconds,
		allowSecretFallback,
	)
	if err != nil {
		h.writeAudit(c, "create_kubeconfig", "failed", "apply rbac failed: "+err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "创建集群资源失败，已拒绝生成不完整的 kubeconfig: " + err.Error()})
		return
	}

	kubeconfigContent, err := kubeconf.BuildKubeconfig(cluster.ClusterID, cluster.APIServer, cluster.CACert, saToken, saNamespace)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	verbSet := make([]string, 0)
	verbSeen := map[string]struct{}{}
	for _, rule := range rules {
		for _, verb := range rule.Verbs {
			if _, ok := verbSeen[verb]; ok {
				continue
			}
			verbSeen[verb] = struct{}{}
			verbSet = append(verbSet, verb)
		}
	}
	rulesJSON, _ := json.Marshal(rules)

	expiresAt := tokenExpiresAt
	record := &store.KubeconfigRecord{
		Name:               strings.TrimSpace(req.Name),
		AccountID:          req.AccountID,
		ClusterID:          req.ClusterID,
		ServiceAccountName: strings.TrimSpace(req.ServiceAccountName),
		Namespace:          saNamespace,
		RoleNamespace:      roleNamespace,
		RoleKind:           roleKind,
		ResourcesJSON:      string(rulesJSON),
		VerbsJSON:          store.ToJSONString(verbSet),
		GeneratedKubeconf:  kubeconfigContent,
		GeneratedRBACYaml:  rbacYaml,
		TokenTTLMode:       ttlMode,
		TokenExpiresAt:     &expiresAt,
		CreatedByUserID:    c.GetInt64("user_id"),
		CreatedByUsername:  c.GetString("username"),
	}
	if err := h.store.CreateKubeconfigRecord(record); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.writeAudit(c, "create_kubeconfig", "success", "created kubeconfig: "+record.Name)
	c.JSON(http.StatusOK, gin.H{
		"message":          "created",
		"id":               record.ID,
		"name":             record.Name,
		"kubeconfig":       kubeconfigContent,
		"rbac_yaml":        rbacYaml,
		"role_kind":        roleKind,
		"download_url":     fmt.Sprintf("/api/kubeconfigs/%d/download", record.ID),
		"token_ttl_mode":   ttlMode,
		"token_expires_at": tokenExpiresAt.Format(time.RFC3339),
	})
}

func (h *Handler) listKubeconfigs(c *gin.Context) {
	accountIDRaw := strings.TrimSpace(c.Query("account_id"))
	clusterIDRaw := strings.TrimSpace(c.Query("cluster_id"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	var accountID, clusterID uint
	if accountIDRaw != "" {
		v, err := strconv.ParseUint(accountIDRaw, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid account_id"})
			return
		}
		accountID = uint(v)
	}
	if clusterIDRaw != "" {
		v, err := strconv.ParseUint(clusterIDRaw, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid cluster_id"})
			return
		}
		clusterID = uint(v)
	}
	items, total, err := h.store.ListKubeconfigRecords(accountID, clusterID, page, size)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	accounts, _ := h.store.ListAccounts()
	accountNameByID := map[uint]string{}
	for _, acct := range accounts {
		accountNameByID[acct.ID] = acct.Name
	}
	clusters, _ := h.store.ListClusters(0)
	clusterNameByID := map[uint]string{}
	for _, cluster := range clusters {
		clusterNameByID[cluster.ID] = cluster.Name
	}

	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		rules := parseStoredPermissionRules(item.ResourcesJSON)
		row := gin.H{
			"id":                   item.ID,
			"name":                 item.Name,
			"account_id":           item.AccountID,
			"account_name":         accountNameByID[item.AccountID],
			"cluster_id":           item.ClusterID,
			"cluster_name":         clusterNameByID[item.ClusterID],
			"service_account_name": item.ServiceAccountName,
			"namespace":            item.Namespace,
			"sa_namespace":         item.Namespace,
			"role_namespace":       item.RoleNamespace,
			"role_kind":            item.RoleKind,
			"rules":                rules,
			"permissions_text":     formatPermissionsText(rules),
			"token_ttl_mode":       item.TokenTTLMode,
			"remaining_days":       remainingTokenDays(item.TokenExpiresAt),
			"created_by":           item.CreatedByUsername,
			"created_at":           item.CreatedAt,
			"download_url":         fmt.Sprintf("/api/kubeconfigs/%d/download", item.ID),
			"rbac_yaml_url":        fmt.Sprintf("/api/kubeconfigs/%d/rbac-yaml", item.ID),
		}
		if item.TokenExpiresAt != nil && !item.TokenExpiresAt.IsZero() {
			row["token_expires_at"] = item.TokenExpiresAt.UTC().Format(time.RFC3339)
		}
		result = append(result, row)
	}
	c.JSON(http.StatusOK, gin.H{
		"kubeconfigs": result,
		"total":       total,
		"page":        page,
		"size":        size,
	})
}

func parseStoredPermissionRules(raw string) []gin.H {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []gin.H{}
	}
	toResult := func(rules []kubeconf.PermissionRule) []gin.H {
		out := make([]gin.H, 0, len(rules))
		for _, rule := range rules {
			if strings.TrimSpace(rule.Resource) == "" {
				continue
			}
			out = append(out, gin.H{
				"api_group": rule.APIGroup,
				"resource":  rule.Resource,
				"verbs":     rule.Verbs,
			})
		}
		return out
	}

	var rules []kubeconf.PermissionRule
	if err := json.Unmarshal([]byte(raw), &rules); err == nil {
		if out := toResult(rules); len(out) > 0 {
			return out
		}
	}
	// Legacy records marshaled without json tags (APIGroup/Resource/Verbs).
	var legacy []struct {
		APIGroup string   `json:"APIGroup"`
		Resource string   `json:"Resource"`
		Verbs    []string `json:"Verbs"`
	}
	if err := json.Unmarshal([]byte(raw), &legacy); err == nil {
		converted := make([]kubeconf.PermissionRule, 0, len(legacy))
		for _, rule := range legacy {
			converted = append(converted, kubeconf.PermissionRule{
				APIGroup: rule.APIGroup,
				Resource: rule.Resource,
				Verbs:    rule.Verbs,
			})
		}
		return toResult(converted)
	}
	return []gin.H{}
}

func formatPermissionsText(rules []gin.H) string {
	parts := make([]string, 0, len(rules))
	for _, rule := range rules {
		resource, _ := rule["resource"].(string)
		apiGroup, _ := rule["api_group"].(string)
		verbsRaw, _ := rule["verbs"].([]string)
		if verbsRaw == nil {
			if arr, ok := rule["verbs"].([]interface{}); ok {
				verbsRaw = make([]string, 0, len(arr))
				for _, v := range arr {
					verbsRaw = append(verbsRaw, fmt.Sprint(v))
				}
			}
		}
		label := resource
		if apiGroup != "" {
			label = apiGroup + "/" + resource
		}
		parts = append(parts, fmt.Sprintf("%s: %s", label, strings.Join(verbsRaw, ",")))
	}
	return strings.Join(parts, "\n")
}

func (h *Handler) downloadKubeconfig(c *gin.Context) {
	idRaw := c.Param("id")
	id, err := strconv.ParseUint(idRaw, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	item, err := h.store.GetKubeconfigRecord(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	filename := strings.ReplaceAll(item.Name, " ", "_") + ".yaml"
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Data(http.StatusOK, "application/x-yaml; charset=utf-8", []byte(item.GeneratedKubeconf))
}

func (h *Handler) getRBACYaml(c *gin.Context) {
	idRaw := c.Param("id")
	id, err := strconv.ParseUint(idRaw, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	item, err := h.store.GetKubeconfigRecord(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	// JSON for modal preview/copy; all authenticated roles that can query may view.
	if strings.EqualFold(c.Query("format"), "yaml") || strings.Contains(c.GetHeader("Accept"), "application/x-yaml") {
		filename := strings.ReplaceAll(item.Name, " ", "_") + "-rbac.yaml"
		c.Header("Content-Disposition", `inline; filename="`+filename+`"`)
		c.Data(http.StatusOK, "application/x-yaml; charset=utf-8", []byte(item.GeneratedRBACYaml))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":        item.ID,
		"name":      item.Name,
		"role_kind": item.RoleKind,
		"rbac_yaml": item.GeneratedRBACYaml,
	})
}

func (h *Handler) deleteKubeconfig(c *gin.Context) {
	idRaw := c.Param("id")
	id, err := strconv.ParseUint(idRaw, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	item, err := h.store.GetKubeconfigRecord(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	cluster, err := h.store.GetClusterByID(item.ClusterID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster not found, cannot delete kubernetes resources"})
		return
	}
	roleKind := strings.TrimSpace(item.RoleKind)
	if roleKind == "" {
		roleKind = "Role"
	}
	if err := k8sclient.DeleteRBACResources(
		cluster.KubeconfigIn,
		item.ServiceAccountName,
		item.Namespace,
		item.RoleNamespace,
		roleKind,
	); err != nil {
		h.writeAudit(c, "delete_kubeconfig", "failed", "delete cluster resources failed: "+err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "删除 Kubernetes 资源失败，已拒绝删除记录: " + err.Error()})
		return
	}
	if err := h.store.DeleteKubeconfigRecord(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.writeAudit(c, "delete_kubeconfig", "success", "deleted kubeconfig: "+item.Name)
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (h *Handler) listUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	keyword := strings.TrimSpace(c.Query("keyword"))
	var roleFilter []store.Role
	if h.currentRole(c) == store.RoleAdmin {
		// admin 仅展示可操作账号，不展示 root / admin
		roleFilter = []store.Role{store.RoleWatcher, store.RoleOperator}
	}
	users, total, err := h.store.ListUsers(page, size, keyword, roleFilter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	result := make([]gin.H, 0, len(users))
	for _, u := range users {
		displayName := strings.TrimSpace(u.DisplayName)
		if displayName == "" {
			displayName = u.Name
		}
		result = append(result, gin.H{
			"id":           u.ID,
			"name":         u.Name,
			"display_name": displayName,
			"phone":        u.Phone,
			"email":        u.Email,
			"role":         string(u.Role),
			"status":       u.Status,
		})
	}
	c.JSON(http.StatusOK, gin.H{"users": result, "total": total, "page": page, "size": size})
}

func (h *Handler) actorCannotOperateTarget(c *gin.Context, target store.Role) bool {
	actor := h.currentRole(c)
	if actor.CanOperateUser(target) {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "admin 仅可操作观察者与操作员账号"})
	return true
}

func (h *Handler) createUser(c *gin.Context) {
	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	req.Phone = strings.TrimSpace(req.Phone)
	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)
	req.Role = strings.TrimSpace(req.Role)
	if req.Username == "" || req.Phone == "" || req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username, phone, email, password are required"})
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}
	role := store.Role(req.Role)
	if !role.IsValidAssignable() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be root, admin, operator or watcher"})
		return
	}
	if h.currentRole(c) == store.RoleAdmin && role != store.RoleWatcher {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin 仅可创建观察者账号"})
		return
	}
	hash, err := h.auth.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash password failed"})
		return
	}
	user := &store.User{
		Name:         req.Username,
		DisplayName:  req.DisplayName,
		Phone:        req.Phone,
		Email:        req.Email,
		PasswordHash: hash,
		Role:         role,
		Status:       "active",
	}
	if err := h.store.CreateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "created"})
}

func (h *Handler) updateUser(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req updateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	phone := strings.TrimSpace(req.Phone)
	email := strings.TrimSpace(req.Email)
	role := store.Role(strings.TrimSpace(req.Role))
	if displayName == "" || phone == "" || email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "display_name, phone, email are required"})
		return
	}
	if !role.IsValidAssignable() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be root, admin, operator or watcher"})
		return
	}
	user, err := h.store.GetUserByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if h.actorCannotOperateTarget(c, user.Role) {
		return
	}
	actor := h.currentRole(c)
	if actor == store.RoleAdmin && !role.IsOperableByAdmin() {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin 仅可将用户角色设置为观察者或操作员"})
		return
	}
	if user.Role == store.RoleRoot && role != store.RoleRoot {
		total, countErr := h.store.CountUsersByRole(store.RoleRoot)
		if countErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": countErr.Error()})
			return
		}
		if total <= 1 {
			c.JSON(http.StatusForbidden, gin.H{"error": "cannot demote the last root user"})
			return
		}
	}
	if err := h.store.UpdateUserInfo(id, displayName, phone, email, role); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

func (h *Handler) updateUserRole(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req updateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	role := store.Role(strings.TrimSpace(req.Role))
	if !role.IsValidAssignable() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be root, admin, operator or watcher"})
		return
	}
	user, err := h.store.GetUserByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if h.actorCannotOperateTarget(c, user.Role) {
		return
	}
	actor := h.currentRole(c)
	if actor == store.RoleAdmin && !role.IsOperableByAdmin() {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin 仅可将用户角色设置为观察者或操作员"})
		return
	}
	if user.Role == store.RoleRoot && role != store.RoleRoot {
		total, countErr := h.store.CountUsersByRole(store.RoleRoot)
		if countErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": countErr.Error()})
			return
		}
		if total <= 1 {
			c.JSON(http.StatusForbidden, gin.H{"error": "cannot demote the last root user"})
			return
		}
	}
	if err := h.store.UpdateUserRole(id, role); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

func (h *Handler) deleteUser(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if id == c.GetInt64("user_id") {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot delete yourself"})
		return
	}
	user, err := h.store.GetUserByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if h.actorCannotOperateTarget(c, user.Role) {
		return
	}
	if user.Role == store.RoleRoot {
		total, countErr := h.store.CountUsersByRole(store.RoleRoot)
		if countErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": countErr.Error()})
			return
		}
		if total <= 1 {
			c.JSON(http.StatusForbidden, gin.H{"error": "cannot delete the last root user"})
			return
		}
	}
	if err := h.store.DeleteUser(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (h *Handler) updateUserStatus(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req updateStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status != "active" && status != "disabled" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be active or disabled"})
		return
	}
	if id == c.GetInt64("user_id") {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot change your own status"})
		return
	}
	user, err := h.store.GetUserByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if h.actorCannotOperateTarget(c, user.Role) {
		return
	}
	if user.Role == store.RoleRoot && status == "disabled" {
		total, countErr := h.store.CountUsersByRole(store.RoleRoot)
		if countErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": countErr.Error()})
			return
		}
		if total <= 1 {
			c.JSON(http.StatusForbidden, gin.H{"error": "cannot disable the last root user"})
			return
		}
	}
	if err := h.store.UpdateUserStatus(id, status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

func (h *Handler) resetUserPassword(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	user, err := h.store.GetUserByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if h.actorCannotOperateTarget(c, user.Role) {
		return
	}
	randomPassword, err := generateRandomPassword(10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "generate password failed"})
		return
	}
	hash, err := h.auth.HashPassword(randomPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash password failed"})
		return
	}
	if err := h.store.UpdateUserPassword(id, hash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	displayName := strings.TrimSpace(user.DisplayName)
	if displayName == "" {
		displayName = user.Name
	}
	_ = h.store.WriteAudit(&store.AuditLog{
		UserID:      user.ID,
		Username:    user.Name,
		DisplayName: displayName,
		Action:      "reset_password",
		Result:      "success",
		IP:          c.ClientIP(),
		Detail:      fmt.Sprintf("password reset by %s", c.GetString("username")),
	})
	c.JSON(http.StatusOK, gin.H{
		"message":  "password reset successfully",
		"password": randomPassword,
	})
}

func (h *Handler) requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := strings.TrimSpace(c.GetHeader("Authorization"))
		if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		token := strings.TrimSpace(header[7:])
		claims, err := h.auth.ParseToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		user, err := h.store.GetUserByID(claims.UserID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		if strings.ToLower(strings.TrimSpace(user.Status)) == "disabled" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "账号已被下线，请重新登录"})
			return
		}
		// 使用数据库中的最新角色，避免权限变更后仍沿用旧 JWT
		c.Set("user_id", user.ID)
		c.Set("username", user.Name)
		c.Set("role", string(user.Role))
		c.Next()
	}
}

func (h *Handler) currentRole(c *gin.Context) store.Role {
	return store.Role(c.GetString("role"))
}

func (h *Handler) requireRole(check func(store.Role) bool, message string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !check(h.currentRole(c)) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": message})
			return
		}
		c.Next()
	}
}

func (h *Handler) requireManageUsers() gin.HandlerFunc {
	return h.requireRole(store.Role.CanManageUsers, "admin or root required")
}

func (h *Handler) requireCreateUsers() gin.HandlerFunc {
	return h.requireRole(store.Role.CanCreateUsers, "admin or root required")
}

func (h *Handler) requireManageDatasource() gin.HandlerFunc {
	return h.requireRole(store.Role.CanManageDatasource, "admin or root required")
}

func (h *Handler) requireViewAudit() gin.HandlerFunc {
	return h.requireRole(store.Role.CanViewAudit, "admin or root required")
}

func (h *Handler) requireCreateKubeconfig() gin.HandlerFunc {
	return h.requireRole(store.Role.CanCreateKubeconfig, "operator, admin or root required")
}

func (h *Handler) requireDownloadKubeconfig() gin.HandlerFunc {
	return h.requireRole(store.Role.CanDownloadKubeconfig, "login required to download")
}

func (h *Handler) requireDeleteKubeconfig() gin.HandlerFunc {
	return h.requireRole(store.Role.CanDeleteKubeconfig, "admin or root required")
}

func (h *Handler) EnsureRootUser(name, phone, email, password string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "root"
	}
	if _, err := h.store.GetUserByName(name); err == nil {
		return nil
	}
	if strings.TrimSpace(password) == "" {
		password = "Root@123456"
	}
	hash, err := h.auth.HashPassword(password)
	if err != nil {
		return err
	}
	return h.store.CreateUser(&store.User{
		Name:         name,
		DisplayName:  "超级管理员",
		Phone:        strings.TrimSpace(phone),
		Email:        strings.TrimSpace(email),
		PasswordHash: hash,
		Role:         store.RoleRoot,
	})
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
