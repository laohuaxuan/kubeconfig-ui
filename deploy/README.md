# 部署说明

## 0. 初始化数据库（可选）

仅表结构、不含业务/数据源数据：

```bash
mysql -h <host> -u <user> -p < deploy/sql/schema.sql
```

应用启动时也会自动建库并 AutoMigrate；未预导入时可跳过本步。

超级管理员首次启动自动创建：用户名 `root`，初始密码 `Root@123456`。

## 1. 构建镜像

在项目根目录执行（根目录 `Dockerfile` 与 `deploy/Dockerfile` 一致）：

```bash
docker build -t your-registry/kubeconfig-ui:latest .
# 或：docker build -f deploy/Dockerfile -t your-registry/kubeconfig-ui:latest .
docker push your-registry/kubeconfig-ui:latest
```

## 2. 修改部署参数

请先根据实际环境修改以下文件：

- `deploy/yamls/configmap.yaml`
  - `database.host`
  - `database.port`
  - `database.user`
  - `database.name`
- `deploy/yamls/secret.yaml`
  - `DB_PASSWORD`
- `deploy/yamls/deployment.yaml`
  - `image: your-registry/kubeconfig-ui:latest`
  - `namespace`（如非 `devops`）

## 3. 应用资源

```bash
kubectl apply -f deploy/yamls/secret.yaml
kubectl apply -f deploy/yamls/configmap.yaml
kubectl apply -f deploy/yamls/deployment.yaml
kubectl apply -f deploy/yamls/service.yaml
```

## 4. 检查状态

```bash
kubectl -n devops get pods -l app=kubeconfig-ui
kubectl -n devops get svc kubeconfig-ui
kubectl -n devops logs deploy/kubeconfig-ui
```

## 5. 本地访问（临时）

```bash
kubectl -n devops port-forward svc/kubeconfig-ui 18080:80
```

访问 `http://127.0.0.1:18080`。

## 注意事项

- 程序默认读取 `CONFIG_FILE` 指向的文件（部署中是 `/app/config.yaml`）。
- `database.password` 为空时，会自动从环境变量 `DB_PASSWORD` 读取。
- 启动时会自动创建数据库（`CREATE DATABASE IF NOT EXISTS`）并执行表迁移，MySQL 用户需具备对应权限。
