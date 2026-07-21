package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Auth     AuthConfig     `yaml:"auth"`
}

type ServerConfig struct {
	Port int `yaml:"port"`
}

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Name     string `yaml:"name"`
	Charset  string `yaml:"charset"`
}

type AuthConfig struct {
	JWTSecret           string `yaml:"jwt_secret"`
	TokenExpiry         string `yaml:"token_expiry"`
	RootInitialName     string `yaml:"root_initial_name"`
	RootInitialPhone    string `yaml:"root_initial_phone"`
	RootInitialEmail    string `yaml:"root_initial_email"`
	RootInitialPassword string `yaml:"root_initial_password"`
	SMTPHost            string `yaml:"smtp_host"`
	SMTPPort            int    `yaml:"smtp_port"`
	SMTPUser            string `yaml:"smtp_user"`
	SMTPPass            string `yaml:"smtp_pass"`
	SMTPFrom            string `yaml:"smtp_from"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config failed: %w", err)
	}

	cfg := &Config{}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config failed: %w", err)
	}

	normalize(cfg)
	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func normalize(cfg *Config) {
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	cfg.Database.Host = strings.TrimSpace(cfg.Database.Host)
	if cfg.Database.Host == "" {
		cfg.Database.Host = "127.0.0.1"
	}
	if cfg.Database.Port == 0 {
		cfg.Database.Port = 3306
	}
	cfg.Database.User = strings.TrimSpace(cfg.Database.User)
	cfg.Database.Password = strings.TrimSpace(cfg.Database.Password)
	if cfg.Database.Password == "" {
		cfg.Database.Password = strings.TrimSpace(os.Getenv("DB_PASSWORD"))
	}
	cfg.Database.Name = strings.TrimSpace(cfg.Database.Name)
	cfg.Database.Charset = strings.TrimSpace(cfg.Database.Charset)
	if cfg.Database.Charset == "" {
		cfg.Database.Charset = "utf8mb4"
	}
	cfg.Auth.JWTSecret = strings.TrimSpace(cfg.Auth.JWTSecret)
	if cfg.Auth.JWTSecret == "" {
		cfg.Auth.JWTSecret = "kubeconfig-ui-secret"
	}
	cfg.Auth.TokenExpiry = strings.TrimSpace(cfg.Auth.TokenExpiry)
	if cfg.Auth.TokenExpiry == "" {
		cfg.Auth.TokenExpiry = "24h"
	}
	cfg.Auth.RootInitialName = strings.TrimSpace(cfg.Auth.RootInitialName)
	if cfg.Auth.RootInitialName == "" {
		cfg.Auth.RootInitialName = "root"
	}
	cfg.Auth.RootInitialPhone = strings.TrimSpace(cfg.Auth.RootInitialPhone)
	if cfg.Auth.RootInitialPhone == "" {
		cfg.Auth.RootInitialPhone = "13000000000"
	}
	cfg.Auth.RootInitialEmail = strings.TrimSpace(cfg.Auth.RootInitialEmail)
	if cfg.Auth.RootInitialEmail == "" {
		cfg.Auth.RootInitialEmail = "root@example.com"
	}
	cfg.Auth.RootInitialPassword = strings.TrimSpace(cfg.Auth.RootInitialPassword)
	if cfg.Auth.RootInitialPassword == "" {
		cfg.Auth.RootInitialPassword = "Root@123456"
	}
	cfg.Auth.SMTPHost = strings.TrimSpace(cfg.Auth.SMTPHost)
	cfg.Auth.SMTPUser = strings.TrimSpace(cfg.Auth.SMTPUser)
	cfg.Auth.SMTPPass = strings.TrimSpace(cfg.Auth.SMTPPass)
	cfg.Auth.SMTPFrom = strings.TrimSpace(cfg.Auth.SMTPFrom)
}

func validate(cfg *Config) error {
	if cfg.Database.User == "" {
		return fmt.Errorf("database.user is required")
	}
	if cfg.Database.Name == "" {
		return fmt.Errorf("database.name is required")
	}
	return nil
}
