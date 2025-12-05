# PostGISCompile

**项目概述**
- 提供在 RHEL/CentOS/Rocky 8/9 系列离线环境下，编译安装 PostgreSQL 与 PostGIS，并自动配置常用扩展与服务的脚本与模板。
- 支持按系统主版本自动选择离线包目录（`packages/rhel8`、`packages/rhel9`），并进行预加载扩展的后置启用与回退。

**目录结构**
- `bin/rockylinux9_install.sh`：Rocky 9 一键编译安装与配置脚本（含服务、扩展、预加载）
- `bin/install.sh`：通用安装脚本，按主版本自动选择 `packages/rhel8` 或 `packages/rhel9`
- `config/postgresql.conf.template`：PostgreSQL 配置模板（末尾保留注释的预加载与 `pg_cron` 参数）
- `config/pg_hba.conf.template`：认证规则模板（本地 `peer`，远程 `scram-sha-256`）
- `scripts/check_offline_environment.sh`：离线环境自检（工具、头文件、RPM 包等）
- `scripts/download_rockylinux9_rpms.sh`：Rocky 9 常用 RPM 批量下载示例脚本
- `packages/rhel8|rhel9/`：离线 RPM 包目录（自动优先使用与系统主版本匹配的目录）
- `docs/`：离线准备与包下载位置说明等文档

**快速开始（Rocky/CentOS/RHEL 8/9）**
- 准备离线包：将所需 RPM 放入 `packages/rhel8` 或 `packages/rhel9`
- 运行通用安装：
  - `sudo bash bin/install.sh`
- 或运行 Rocky9 专用脚本：
  - `sudo bash bin/rockylinux9_install.sh`

**关键行为与配置**
- 主版本自动选择离线包目录：`bin/install.sh:172-201`（已重写，仅按主版本 8/9 选择 `OS_SHORT`）
- 服务配置：创建 `postgresql-custom`，使用 `RuntimeDirectory=postgresql` 自动创建 `/var/run/postgresql` 套接字目录
- 套接字目录：模板中 `unix_socket_directories = '/var/run/postgresql,/tmp'`
- 环境变量：安装后写入 `PGHOST=/var/run/postgresql`，本地套接字默认免密连接
- 认证：
  - 本地套接字：`peer`（免密）
  - IPv4/IPv6：`scram-sha-256`（推荐），在 `config/pg_hba.conf.template:6-18`
- 密码：使用脚本变量设置，不交互输入：`bin/rockylinux9_install.sh:34` 与 `bin/rockylinux9_install.sh:808-817`

**预加载扩展策略**
- 模板末尾保留注释，不在初始化阶段加载：`config/postgresql.conf.template:66-69`
- 安装完成后由脚本在数据目录 `postgresql.conf` 中取消注释并重启：`bin/rockylinux9_install.sh:762-810`
- 预加载库列表（按模板注释行）：`postgis,pg_stat_statements,pg_stat_kcache,pg_wait_sampling,pg_qualstats,pg_stat_monitor,pg_cron`
- `pg_cron` 参数：`cron.database_name = 'postgres'`
- 重启就绪等待：`bin/rockylinux9_install.sh:689-707` 使用 `pg_isready` 轮询

**回退与排错**
- 若重启失败，脚本自动剥离可能不兼容库并打印最新日志：`bin/rockylinux9_install.sh:756-816`
- 常见不兼容：`pg_stat_monitor` 版本与 PG 主版本不匹配、`pg_cron` 未满足依赖
- 查看日志：`$PGDATA/pg_log/postgresql-*.log`

**连接示例**
- 本地免密（套接字）：
  - `sudo -u postgres PGHOST=/var/run/postgresql psql --no-password`
- 远程/TCP（需要密码）：
  - `psql -h <server-ip> -p 5432 -U postgres`
  - 如果客户端不支持 `scram-sha-256`，临时将 `pg_hba.conf` 的远程规则改为 `md5` 并重载配置

**注意事项**
- Windows 上 `pg_cron` 不支持后台工作进程；建议在 Linux 实例启用或使用替代方案（如 `pgAgent`/系统计划任务）
- 生产环境不建议 `0.0.0.0/0` 全局开放，请改为指定网段并配合防火墙
