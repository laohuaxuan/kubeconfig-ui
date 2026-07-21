package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"kubeconfig-ui/internal/auth"
	"kubeconfig-ui/internal/config"
	"kubeconfig-ui/internal/httpapi"
	"kubeconfig-ui/internal/store"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	configPath := os.Getenv("CONFIG_FILE")
	if configPath == "" {
		configPath = "config.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	if err := createDatabaseIfNotExist(cfg); err != nil {
		log.Fatalf("create database failed: %v", err)
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=True&loc=Local",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
		cfg.Database.Charset,
	)
	db, err := store.New(dsn)
	if err != nil {
		log.Fatalf("open database failed: %v", err)
	}

	tokenExpiry, err := time.ParseDuration(cfg.Auth.TokenExpiry)
	if err != nil {
		log.Fatalf("parse token_expiry failed: %v", err)
	}
	authSvc := auth.New(db, auth.Config{
		JWTSecret:   cfg.Auth.JWTSecret,
		TokenExpiry: tokenExpiry,
		SMTPHost:    cfg.Auth.SMTPHost,
		SMTPPort:    cfg.Auth.SMTPPort,
		SMTPUser:    cfg.Auth.SMTPUser,
		SMTPPass:    cfg.Auth.SMTPPass,
		SMTPFrom:    cfg.Auth.SMTPFrom,
	})
	handler := httpapi.NewHandler(db, authSvc)
	if err := handler.EnsureRootUser(
		cfg.Auth.RootInitialName,
		cfg.Auth.RootInitialPhone,
		cfg.Auth.RootInitialEmail,
		cfg.Auth.RootInitialPassword,
	); err != nil {
		log.Fatalf("ensure root user failed: %v", err)
	}

	router := gin.Default()
	handler.RegisterRoutes(router)
	registerFrontend(router)

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	log.Printf("server started at %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("start server failed: %v", err)
	}
}

func createDatabaseIfNotExist(cfg *config.Config) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?charset=%s&parseTime=True&loc=Local",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Charset,
	)
	sqlDB, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	_, err = sqlDB.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", cfg.Database.Name))
	return err
}

func registerFrontend(router *gin.Engine) {
	distPath := "frontend/dist"
	if _, err := os.Stat(distPath); err != nil {
		return
	}

	router.Static("/assets", distPath+"/assets")
	router.GET("/", func(c *gin.Context) {
		c.File(distPath + "/index.html")
	})
	router.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		if len(path) >= 4 && path[:4] == "/api" {
			c.JSON(404, gin.H{"error": "not found"})
			return
		}
		c.File(distPath + "/index.html")
	})
}
