-- kubeconfig-ui MySQL schema (structure only, no data)
-- Generated for new environment deployment.
-- Usage:
--   mysql -h <host> -u <user> -p < deploy/sql/schema.sql
-- Note: application also AutoMigrate on startup; this file is for optional pre-provisioning.


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `kubeconfig_ui` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;

USE `kubeconfig_ui`;
DROP TABLE IF EXISTS `aliyun_accounts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `aliyun_accounts` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `name` varchar(120) NOT NULL,
  `access_key_id` varchar(200) NOT NULL,
  `access_key_secret` varchar(300) NOT NULL,
  `region` varchar(64) NOT NULL,
  `account_code` varchar(120) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_aliyun_accounts_name` (`name`),
  UNIQUE KEY `idx_aliyun_accounts_account_code` (`account_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `audit_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_logs` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(3) DEFAULT NULL,
  `user_id` bigint DEFAULT NULL,
  `username` varchar(100) DEFAULT NULL,
  `action` varchar(60) DEFAULT NULL,
  `result` varchar(20) DEFAULT NULL,
  `ip` varchar(64) DEFAULT NULL,
  `detail` varchar(1000) DEFAULT NULL,
  `display_name` varchar(120) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_audit_logs_result` (`result`),
  KEY `idx_audit_logs_user_id` (`user_id`),
  KEY `idx_audit_logs_username` (`username`),
  KEY `idx_audit_logs_action` (`action`),
  KEY `idx_audit_logs_display_name` (`display_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `k8s_clusters`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `k8s_clusters` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `account_id` bigint unsigned NOT NULL,
  `name` varchar(120) NOT NULL,
  `cluster_id` varchar(120) NOT NULL,
  `api_server` varchar(500) NOT NULL,
  `ca_cert` text NOT NULL,
  `kubeconfig_in` text,
  `version` varchar(64) DEFAULT NULL,
  `provider` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_k8s_clusters_cluster_id` (`cluster_id`),
  KEY `idx_k8s_clusters_account_id` (`account_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `kubeconfig_records`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `kubeconfig_records` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `name` varchar(120) NOT NULL,
  `account_id` bigint unsigned NOT NULL,
  `cluster_id` bigint unsigned NOT NULL,
  `service_account_name` varchar(120) NOT NULL,
  `namespace` varchar(120) NOT NULL,
  `resources_json` text NOT NULL,
  `verbs_json` text NOT NULL,
  `generated_kubeconf` longtext NOT NULL,
  `generated_rbac_yaml` longtext NOT NULL,
  `created_by_user_id` bigint DEFAULT NULL,
  `created_by_username` varchar(100) DEFAULT NULL,
  `role_kind` varchar(32) DEFAULT 'Role',
  `role_namespace` varchar(120) DEFAULT NULL,
  `token_ttl_mode` varchar(32) DEFAULT NULL,
  `token_expires_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_kubeconfig_records_name` (`name`),
  KEY `idx_kubeconfig_records_account_id` (`account_id`),
  KEY `idx_kubeconfig_records_cluster_id` (`cluster_id`),
  KEY `idx_kubeconfig_records_created_by_user_id` (`created_by_user_id`),
  KEY `idx_kubeconfig_records_created_by_username` (`created_by_username`),
  KEY `idx_kubeconfig_records_token_expires_at` (`token_expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `password_reset_request_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `password_reset_request_logs` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(3) DEFAULT NULL,
  `user_id` bigint DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `ip` varchar(64) DEFAULT NULL,
  `device` varchar(512) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_password_reset_request_logs_user_id` (`user_id`),
  KEY `idx_password_reset_request_logs_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `reset_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `reset_tokens` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  `user_id` bigint DEFAULT NULL,
  `token` varchar(64) DEFAULT NULL,
  `expires_at` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_reset_tokens_user_id` (`user_id`),
  UNIQUE KEY `idx_reset_tokens_token` (`token`),
  KEY `idx_reset_tokens_expires_at` (`expires_at`),
  KEY `idx_reset_tokens_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `phone` varchar(30) DEFAULT NULL,
  `email` varchar(120) DEFAULT NULL,
  `password_hash` varchar(255) DEFAULT NULL,
  `role` varchar(20) DEFAULT 'watcher',
  `status` varchar(20) DEFAULT 'active',
  `display_name` varchar(120) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_users_name` (`name`),
  UNIQUE KEY `idx_users_phone` (`phone`),
  UNIQUE KEY `idx_users_email` (`email`),
  KEY `idx_users_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
--
-- WARNING: can't read the INFORMATION_SCHEMA.libraries table. It's most probably an old server 8.0.34.
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

