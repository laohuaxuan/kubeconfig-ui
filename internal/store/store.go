package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type Role string

const (
	RoleRoot     Role = "root"
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleWatcher  Role = "watcher"
)

func (r Role) IsValidAssignable() bool {
	switch r {
	case RoleRoot, RoleAdmin, RoleOperator, RoleWatcher:
		return true
	default:
		return false
	}
}

func (r Role) CanManageUsers() bool { return r == RoleRoot || r == RoleAdmin }
func (r Role) CanCreateUsers() bool { return r == RoleRoot || r == RoleAdmin }
func (r Role) IsOperableByAdmin() bool {
	return r == RoleWatcher || r == RoleOperator
}
func (r Role) CanOperateUser(target Role) bool {
	if r == RoleRoot {
		return true
	}
	if r == RoleAdmin {
		return target.IsOperableByAdmin()
	}
	return false
}
func (r Role) CanManageDatasource() bool {
	return r == RoleRoot || r == RoleAdmin
}
func (r Role) CanViewAudit() bool {
	return r == RoleRoot || r == RoleAdmin
}
func (r Role) CanCreateKubeconfig() bool {
	return r == RoleRoot || r == RoleAdmin || r == RoleOperator
}
func (r Role) CanDownloadKubeconfig() bool {
	return r == RoleRoot || r == RoleAdmin || r == RoleOperator || r == RoleWatcher
}
func (r Role) CanDeleteKubeconfig() bool {
	return r == RoleRoot || r == RoleAdmin
}

type User struct {
	ID           int64 `gorm:"primaryKey;autoIncrement"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`
	Name         string         `gorm:"uniqueIndex;size:100"`
	DisplayName  string         `gorm:"size:120"` // 显示名
	Phone        string         `gorm:"uniqueIndex;size:30"`
	Email        string         `gorm:"uniqueIndex;size:120"`
	PasswordHash string         `gorm:"size:255"`
	Role         Role           `gorm:"size:20;default:watcher"`
	Status       string         `gorm:"size:20;default:active"` // active/disabled
}

type ResetToken struct {
	ID        int64 `gorm:"primaryKey;autoIncrement"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
	UserID    int64          `gorm:"uniqueIndex"`
	Token     string         `gorm:"uniqueIndex;size:64"`
	ExpiresAt int64          `gorm:"index"`
}

type PasswordResetRequestLog struct {
	ID        int64 `gorm:"primaryKey;autoIncrement"`
	CreatedAt time.Time
	UserID    int64  `gorm:"index"`
	Email     string `gorm:"size:100;index"`
	IP        string `gorm:"size:64"`
	Device    string `gorm:"size:512"`
}

type AuditLog struct {
	ID          int64 `gorm:"primaryKey;autoIncrement"`
	CreatedAt   time.Time
	UserID      int64  `gorm:"index"`
	Username    string `gorm:"size:100;index"`
	DisplayName string `gorm:"size:120;index"` // 显示名（写入时快照）
	Action      string `gorm:"size:60;index"`  // login/logout/create_kubeconfig...
	Result      string `gorm:"size:20;index"`  // success/failed
	IP          string `gorm:"size:64"`
	Detail      string `gorm:"size:1000"`
}

type AliyunAccount struct {
	ID              uint `gorm:"primaryKey"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Name            string `gorm:"size:120;uniqueIndex;not null"` // 业务组名称
	AccountCode     string `gorm:"size:120;uniqueIndex;not null"` // 兼容旧字段，默认等于名称
	AccessKeyID     string `gorm:"size:200"`
	AccessKeySecret string `gorm:"size:300"`
	Region          string `gorm:"size:64"`
}

type K8sCluster struct {
	ID           uint `gorm:"primaryKey"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	AccountID    uint   `gorm:"index;not null"`
	Name         string `gorm:"size:120;not null"`
	ClusterID    string `gorm:"size:120;index;not null"`
	Version      string `gorm:"size:64"` // 集群版本，如 1.28.3
	Provider     string `gorm:"size:64"` // 集群提供商
	APIServer    string `gorm:"size:500;not null"`
	CACert       string `gorm:"type:text;not null"`
	KubeconfigIn string `gorm:"type:text"`
}

type KubeconfigRecord struct {
	ID                 uint `gorm:"primaryKey"`
	CreatedAt          time.Time
	UpdatedAt          time.Time
	Name               string `gorm:"size:120;index;not null"`
	AccountID          uint   `gorm:"index;not null"`
	ClusterID          uint   `gorm:"index;not null"`
	ServiceAccountName string `gorm:"size:120;not null"`
	Namespace          string `gorm:"size:120;not null"`    // ServiceAccount 命名空间
	RoleNamespace      string `gorm:"size:120"`             // Role/RoleBinding 命名空间（Role 时使用）
	RoleKind           string `gorm:"size:32;default:Role"` // Role / ClusterRole
	ResourcesJSON      string `gorm:"type:text;not null"`   // permission rules JSON
	VerbsJSON          string `gorm:"type:text;not null"`   // flattened verbs for兼容展示
	GeneratedKubeconf  string `gorm:"type:longtext;not null"`
	GeneratedRBACYaml  string `gorm:"type:longtext;not null"`
	TokenTTLMode       string     `gorm:"size:32"` // temporary / custom / long
	TokenExpiresAt     *time.Time `gorm:"index"`   // ServiceAccount Token 过期时间
	CreatedByUserID    int64  `gorm:"index"`
	CreatedByUsername  string `gorm:"size:100;index"`
}

type Store struct {
	db *gorm.DB
}

func New(dsn string) (*Store, error) {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open database failed: %w", err)
	}
	if err := db.AutoMigrate(
		&User{},
		&ResetToken{},
		&PasswordResetRequestLog{},
		&AuditLog{},
		&AliyunAccount{},
		&K8sCluster{},
		&KubeconfigRecord{},
	); err != nil {
		return nil, fmt.Errorf("migrate database failed: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) CreateUser(user *User) error { return s.db.Create(user).Error }
func (s *Store) ListUsers(page, pageSize int, keyword string, roles []Role) ([]User, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	var items []User
	var total int64
	query := s.db.Model(&User{}).Order("id asc")
	if len(roles) > 0 {
		query = query.Where("role IN ?", roles)
	}
	keyword = "%" + keyword + "%"
	if keyword != "%%" {
		query = query.Where("name LIKE ? OR display_name LIKE ? OR phone LIKE ? OR email LIKE ?", keyword, keyword, keyword, keyword)
	}
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}
func (s *Store) GetUserByID(id int64) (*User, error) {
	var user User
	if err := s.db.First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}
func (s *Store) GetUserByPhone(phone string) (*User, error) {
	var user User
	if err := s.db.Where("phone = ?", phone).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetUserByEmail(email string) (*User, error) {
	var user User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetUserByName(name string) (*User, error) {
	var user User
	if err := s.db.Where("name = ?", name).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}
func (s *Store) CountUsersByRole(role Role) (int64, error) {
	var total int64
	err := s.db.Model(&User{}).Where("role = ?", role).Count(&total).Error
	return total, err
}
func (s *Store) UpdateUserProfile(id int64, displayName, phone, email string) error {
	return s.db.Model(&User{}).Where("id = ?", id).Updates(map[string]interface{}{
		"display_name": displayName,
		"phone":        phone,
		"email":        email,
	}).Error
}
func (s *Store) UpdateUserInfo(id int64, displayName, phone, email string, role Role) error {
	return s.db.Model(&User{}).Where("id = ?", id).Updates(map[string]interface{}{
		"display_name": displayName,
		"phone":        phone,
		"email":        email,
		"role":         role,
	}).Error
}
func (s *Store) UpdateUserRole(id int64, role Role) error {
	return s.db.Model(&User{}).Where("id = ?", id).Update("role", role).Error
}
func (s *Store) UpdateUserStatus(id int64, status string) error {
	return s.db.Model(&User{}).Where("id = ?", id).Update("status", status).Error
}
func (s *Store) UpdateUserPassword(id int64, hash string) error {
	return s.db.Model(&User{}).Where("id = ?", id).Update("password_hash", hash).Error
}
func (s *Store) DeleteUser(id int64) error { return s.db.Delete(&User{}, id).Error }

func (s *Store) SaveResetToken(token *ResetToken) error {
	return s.db.Create(token).Error
}

func (s *Store) GetResetToken(token string) (*ResetToken, error) {
	var rt ResetToken
	if err := s.db.Where("token = ?", token).First(&rt).Error; err != nil {
		return nil, err
	}
	return &rt, nil
}

func (s *Store) GetResetTokenByUserID(userID int64) (*ResetToken, error) {
	var rt ResetToken
	if err := s.db.Where("user_id = ?", userID).First(&rt).Error; err != nil {
		return nil, err
	}
	return &rt, nil
}

func (s *Store) DeleteResetToken(userID int64) error {
	return s.db.Unscoped().Where("user_id = ?", userID).Delete(&ResetToken{}).Error
}

func (s *Store) DeleteResetTokenByToken(token string) error {
	return s.db.Unscoped().Where("token = ?", token).Delete(&ResetToken{}).Error
}

func (s *Store) CreatePasswordResetRequestLog(log *PasswordResetRequestLog) error {
	return s.db.Create(log).Error
}

func (s *Store) CountPasswordResetRequestsSince(userID int64, since time.Time) (int64, error) {
	var count int64
	if err := s.db.Model(&PasswordResetRequestLog{}).
		Where("user_id = ? AND created_at >= ?", userID, since).
		Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) WriteAudit(log *AuditLog) error {
	return s.db.Create(log).Error
}

func auditKeywordVariants(keyword string) []string {
	seen := map[string]struct{}{keyword: {}}
	out := []string{keyword}
	aliases := map[string]string{
		"登录":           "login",
		"登出":           "logout",
		"注册":           "register",
		"创建kubeconfig": "create_kubeconfig",
		"删除kubeconfig": "delete_kubeconfig",
		"成功":           "success",
		"失败":           "failed",
	}
	for zh, en := range aliases {
		if strings.Contains(keyword, zh) || strings.Contains(zh, keyword) {
			if _, ok := seen[en]; !ok {
				seen[en] = struct{}{}
				out = append(out, en)
			}
		}
		if strings.Contains(keyword, en) || strings.EqualFold(keyword, en) {
			if _, ok := seen[zh]; !ok {
				seen[zh] = struct{}{}
				out = append(out, zh)
			}
		}
	}
	return out
}
func (s *Store) ListAuditLogs(page, pageSize int, keyword string, startAt, endAt *time.Time) ([]AuditLog, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	var items []AuditLog
	var total int64
	query := s.db.Model(&AuditLog{}).
		Joins("LEFT JOIN users ON users.id = audit_logs.user_id AND users.deleted_at IS NULL")
	if keyword = strings.TrimSpace(keyword); keyword != "" {
		likes := auditKeywordVariants(keyword)
		var parts []string
		var args []interface{}
		for _, term := range likes {
			like := "%" + term + "%"
			parts = append(parts, "(audit_logs.username LIKE ? OR audit_logs.display_name LIKE ? OR COALESCE(users.display_name,'') LIKE ? OR COALESCE(users.name,'') LIKE ? OR audit_logs.action LIKE ? OR audit_logs.result LIKE ? OR audit_logs.ip LIKE ? OR audit_logs.detail LIKE ?)")
			args = append(args, like, like, like, like, like, like, like, like)
		}
		query = query.Where(strings.Join(parts, " OR "), args...)
	}
	if startAt != nil {
		query = query.Where("audit_logs.created_at >= ?", *startAt)
	}
	if endAt != nil {
		query = query.Where("audit_logs.created_at <= ?", *endAt)
	}
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * pageSize
	if err := query.Select("audit_logs.*").Order("audit_logs.created_at desc").Offset(offset).Limit(pageSize).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	// Fill missing display names from current user profile for legacy rows.
	userIDs := make([]int64, 0)
	seen := map[int64]struct{}{}
	for _, item := range items {
		if strings.TrimSpace(item.DisplayName) != "" || item.UserID <= 0 {
			continue
		}
		if _, ok := seen[item.UserID]; ok {
			continue
		}
		seen[item.UserID] = struct{}{}
		userIDs = append(userIDs, item.UserID)
	}
	if len(userIDs) > 0 {
		var users []User
		_ = s.db.Select("id", "name", "display_name").Where("id IN ?", userIDs).Find(&users).Error
		byID := map[int64]User{}
		for _, u := range users {
			byID[u.ID] = u
		}
		for i := range items {
			if strings.TrimSpace(items[i].DisplayName) != "" {
				continue
			}
			if u, ok := byID[items[i].UserID]; ok {
				if dn := strings.TrimSpace(u.DisplayName); dn != "" {
					items[i].DisplayName = dn
				} else {
					items[i].DisplayName = u.Name
				}
			}
		}
	}
	return items, total, nil
}

func (s *Store) CreateAccount(account *AliyunAccount) error { return s.db.Create(account).Error }
func (s *Store) GetAccountByID(id uint) (*AliyunAccount, error) {
	var item AliyunAccount
	if err := s.db.First(&item, id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}
func (s *Store) UpdateAccount(account *AliyunAccount) error {
	return s.db.Model(&AliyunAccount{}).Where("id = ?", account.ID).Updates(map[string]any{
		"name":         account.Name,
		"account_code": account.AccountCode,
	}).Error
}
func (s *Store) ListAccounts() ([]AliyunAccount, error) {
	var items []AliyunAccount
	if err := s.db.Order("name asc").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}
func (s *Store) DeleteAccount(id uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("account_id = ?", id).Delete(&K8sCluster{}).Error; err != nil {
			return err
		}
		return tx.Delete(&AliyunAccount{}, id).Error
	})
}

func (s *Store) CreateCluster(cluster *K8sCluster) error { return s.db.Create(cluster).Error }
func (s *Store) UpdateCluster(cluster *K8sCluster) error {
	return s.db.Model(&K8sCluster{}).Where("id = ?", cluster.ID).Updates(map[string]any{
		"account_id":    cluster.AccountID,
		"name":          cluster.Name,
		"version":       cluster.Version,
		"provider":      cluster.Provider,
		"api_server":    cluster.APIServer,
		"ca_cert":       cluster.CACert,
		"kubeconfig_in": cluster.KubeconfigIn,
	}).Error
}
func (s *Store) DeleteCluster(id uint) error {
	return s.db.Delete(&K8sCluster{}, id).Error
}
func (s *Store) ListClusters(accountID uint) ([]K8sCluster, error) {
	var items []K8sCluster
	query := s.db.Order("id desc")
	if accountID > 0 {
		query = query.Where("account_id = ?", accountID)
	}
	if err := query.Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}
func (s *Store) GetClusterByID(id uint) (*K8sCluster, error) {
	var cluster K8sCluster
	if err := s.db.First(&cluster, id).Error; err != nil {
		return nil, err
	}
	return &cluster, nil
}

func (s *Store) CreateKubeconfigRecord(record *KubeconfigRecord) error {
	return s.db.Create(record).Error
}
func (s *Store) ListKubeconfigRecords(accountID, clusterID uint, page, pageSize int) ([]KubeconfigRecord, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 200 {
		pageSize = 200
	}
	var items []KubeconfigRecord
	var total int64
	query := s.db.Model(&KubeconfigRecord{})
	if accountID > 0 {
		query = query.Where("account_id = ?", accountID)
	}
	if clusterID > 0 {
		query = query.Where("cluster_id = ?", clusterID)
	}
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * pageSize
	if err := query.Order("id desc").Offset(offset).Limit(pageSize).Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}
func (s *Store) GetKubeconfigRecord(id uint) (*KubeconfigRecord, error) {
	var item KubeconfigRecord
	if err := s.db.First(&item, id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}
func (s *Store) DeleteKubeconfigRecord(id uint) error {
	return s.db.Delete(&KubeconfigRecord{}, id).Error
}

func ToJSONString(items []string) string {
	raw, _ := json.Marshal(items)
	return string(raw)
}
