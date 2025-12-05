#!/bin/bash

# PostgreSQL 与 PostGIS 自动编译安装脚本 - RHEL 系列专用
# 基于 RHEL 的稳定系统,全离线安装
# 依赖包优先使用 RPM,无 RPM 则编译安装
# 版本适配参考: https://trac.osgeo.org/postgis/wiki/UsersWikiPostgreSQLPostGIS

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 安装配置参数
PREFIX_BASE="/opt/postgresql"
PREFIX_PG="${PREFIX_BASE}/postgres"
PREFIX_POSTGIS="${PREFIX_PG}"
PREFIX_DEPS="${PREFIX_BASE}/deps"
PG_DATA_DIR="${PREFIX_BASE}/data"
SRC_DIR="/tmp/pg_build"
INSTALLER_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DOWNLOAD_DIR="${INSTALLER_DIR}/packages"

# RHEL 版本信息
# 参考: https://trac.osgeo.org/postgis/wiki/UsersWikiPostgreSQLPostGIS
# 已验证版本:
# 9系列(rocky,alam,stream) 
# 18.1 + 3.6.1
# 18.1 + 3.5.4
# 17.7 + 3.6.1
# 17.7 + 3.5.4

PG_VERSION="17.7"
POSTGIS_VERSION="3.6.1"

# postgres 数据库密码
PG_PASSWORD="Lunz2017"

# 日志函数
echo_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

echo_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

echo_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 配置DNF本地仓库并生成元数据
setup_local_dnf_repo() {
    LOCAL_REPO_DIR="${DOWNLOAD_DIR}/${OS_SHORT}"
    LOCAL_REPO_ID="local-offline"
    LOCAL_REPO_FILE="/etc/yum.repos.d/${LOCAL_REPO_ID}.repo"

    if [ ! -d "${LOCAL_REPO_DIR}" ]; then
        echo_error "未找到本地包目录：${LOCAL_REPO_DIR}"
        exit 1
    fi

    if ! command -v createrepo_c >/dev/null 2>&1; then
        if compgen -G "${LOCAL_REPO_DIR}/createrepo_c-*.rpm" > /dev/null; then
            echo_info "正在使用本地RPM安装 createrepo_c..."
            dnf -y --disablerepo='*' --setopt=install_weak_deps=False --nogpgcheck --nobest --skip-broken install \
                "${LOCAL_REPO_DIR}/createrepo_c-"*.rpm \
                || echo_warning "createrepo_c 本地安装未完成或部分依赖缺失，继续"
        fi
    fi

    if command -v createrepo_c >/dev/null 2>&1; then
        createrepo_c "${LOCAL_REPO_DIR}" >/dev/null 2>&1 || true
    elif command -v createrepo >/dev/null 2>&1; then
        createrepo "${LOCAL_REPO_DIR}" >/dev/null 2>&1 || true
    fi

    if [ -f "${LOCAL_REPO_DIR}/repodata/repomd.xml" ]; then
        cat > "${LOCAL_REPO_FILE}" <<EOF
[${LOCAL_REPO_ID}]
name=Local Offline Repo
baseurl=file://${LOCAL_REPO_DIR}
enabled=1
gpgcheck=0
EOF
        dnf clean all >/dev/null 2>&1 || true
        dnf makecache --disablerepo='*' --enablerepo="${LOCAL_REPO_ID}" >/dev/null 2>&1 || true
    else
        rm -f "${LOCAL_REPO_FILE}" 2>/dev/null || true
        echo_warning "未检测到本地仓库元数据，将改用本地RPM文件安装"
    fi
}

# 使用DNF从本地仓库或本地RPM文件安装一组软件包
dnf_install_local() {
    local mode="${1:-optional}"; shift
    local pkgs=("$@")
    local repo_id="local-offline"
    local repo_dir="${DOWNLOAD_DIR}/${OS_SHORT}"

    if [ ${#pkgs[@]} -eq 0 ]; then
        return 0
    fi

    local have_repo=0
    if [ -f "/etc/yum.repos.d/${repo_id}.repo" ] && [ -f "${repo_dir}/repodata/repomd.xml" ]; then
        have_repo=1
    fi

    if [ ${have_repo} -eq 1 ]; then
        if dnf -y --disablerepo='*' --enablerepo="${repo_id}" --setopt=install_weak_deps=False --nogpgcheck --nobest install "${pkgs[@]}"; then
            echo_success "DNF 安装完成：${pkgs[*]}"
            return 0
        fi
        echo_warning "DNF仓库安装失败，尝试以本地RPM文件直接安装..."
    fi

    local files=()
    for p in "${pkgs[@]}"; do
        local matches=("${repo_dir}/"${p}*.rpm)
        if [ ${#matches[@]} -eq 0 ]; then
            if [ "${mode}" = "required" ]; then
                echo_error "缺少必需包或RPM：${p}"
                exit 1
            else
                echo_warning "未找到匹配RPM：${p}，跳过"
            fi
            continue
        fi
        files+=("${matches[@]}")
    done

    if [ ${#files[@]} -eq 0 ]; then
        return 0
    fi

    if dnf -y --disablerepo='*' --setopt=install_weak_deps=False --nogpgcheck --nobest install "${files[@]}"; then
        echo_success "DNF 本地RPM安装完成：${pkgs[*]}"
    else
        echo_error "DNF 安装失败：${pkgs[*]}"
        if [ "${mode}" = "required" ]; then
            exit 1
        fi
    fi
}

# 检查 root 权限
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo_error "请以root用户运行此脚本"
        exit 1
    fi
    echo_success "用户权限检查通过"
}

# 导入 GPG 密钥
import_gpg_key() {
    local key_file="${DOWNLOAD_DIR}/${OS_SHORT}/RPM-GPG-KEY"
    if [ -f "$key_file" ]; then
        echo_info "导入 ${OS_SHORT} GPG 密钥..."
        rpm --import "$key_file" || {
            echo_warning "GPG 密钥导入失败，继续安装但可能提示 NOKEY"
            return 0
        }
        echo_success "GPG 密钥导入完成"
    else
        echo_warning "未找到 GPG 密钥文件，路径: $key_file，继续安装"
    fi
}

detect_os() {
    echo_info "正在检测操作系统类型和版本..."

    if [ -f /etc/os-release ]; then
        OS_TYPE=$(grep -oP '^NAME="\K[^"]+' /etc/os-release)
        OS_VERSION=$(grep -oP '^VERSION_ID="\K[^"]+' /etc/os-release)
    else
        echo_error "无法识别操作系统类型"
        exit 1
    fi

    MAJOR_VERSION=$(echo "$OS_VERSION" | awk -F'.' '{print $1}')
    if [ -z "$MAJOR_VERSION" ]; then
        echo_error "无法解析系统主版本号: $OS_VERSION"
        exit 1
    fi

    if [ "$MAJOR_VERSION" = "9" ]; then
        echo_success "操作系统检测完成: $OS_TYPE $OS_VERSION (主版本 9)"
        if [ -d "${DOWNLOAD_DIR}/rhel9" ]; then
            OS_SHORT="rhel9"
        elif [ -d "${DOWNLOAD_DIR}/rhel8" ]; then
            echo_warning "未找到 rhel9 包目录，回退使用 rhel8 包目录"
            OS_SHORT="rhel8"
        else
            echo_error "未找到可用的离线包目录，请在 packages/rhel9 或 packages/rhel8 下准备RPM"
            exit 1
        fi
    elif [ "$MAJOR_VERSION" = "8" ]; then
        echo_success "操作系统检测完成: $OS_TYPE $OS_VERSION (主版本 8)"
        if [ -d "${DOWNLOAD_DIR}/rhel8" ]; then
            OS_SHORT="rhel8"
        elif [ -d "${DOWNLOAD_DIR}/rhel9" ]; then
            echo_warning "未找到 rhel8 包目录，回退使用 rhel9 包目录"
            OS_SHORT="rhel9"
        else
            echo_error "未找到可用的离线包目录，请在 packages/rhel8 或 packages/rhel9 下准备RPM"
            exit 1
        fi
    else
        echo_warning "当前系统主版本: $MAJOR_VERSION，脚本主要适配 8/9，尝试继续"
        if [ -d "${DOWNLOAD_DIR}/rhel9" ]; then
            OS_SHORT="rhel9"
        elif [ -d "${DOWNLOAD_DIR}/rhel8" ]; then
            OS_SHORT="rhel8"
        else
            echo_error "未找到可用的离线包目录，请在 packages/rhel8 或 packages/rhel9 下准备RPM"
            exit 1
        fi
    fi
}

# 安装系统依赖
install_system_deps() {
    echo_info "正在安装基础编译工具和系统依赖..."

    import_gpg_key
    setup_local_dnf_repo

    dnf_install_local optional \
        lsof tar gzip bzip2 unzip vim htop

    dnf_install_local optional \
        binutils gcc gcc-c++ make flex m4 pkgconf pkgconf-pkg-config libpkgconf glibc-devel libmpc cpp libstdc++-devel createrepo_c bison

    dnf_install_local optional \
        cmake cmake-filesystem cmake-data cmake-rpm-macros libuv emacs-filesystem vim-filesystem

    dnf_install_local required \
        openssl-devel openssl-libs readline-devel zlib-devel

    dnf_install_local required \
        perl

    dnf_install_local required \
        python3 python3-devel

    dnf_install_local required \
        libicu libicu-devel libxml2 libxml2-devel xz-devel

    dnf_install_local required \
        avahi avahi-libs avahi-devel avahi-compat-libdns_sd avahi-compat-libdns_sd-devel libevent libevent-devel

    dnf_install_local required \
        libselinux libselinux-devel libsepol libsepol-devel pcre2 pcre2-utf16 pcre2-utf32 pcre2-devel

    dnf_install_local required \
        keyutils-libs-devel libcom_err-devel libverto-devel libkadm5 krb5-libs krb5-devel

    dnf_install_local required \
        openldap openldap-devel pam pam-devel

    dnf_install_local optional \
        json-c sqlite sqlite-devel

    dnf_install_local required \
        libjpeg-turbo libwebp jbigkit-libs libtiff libtiff-devel proj-data libcurl libcurl-devel libpng libpng-devel

    dnf_install_local required \
        proj proj-devel geos geos-devel

    dnf_install_local optional \
        SFCGAL SFCGAL-devel

    dnf_install_local required \
        unixODBC
    dnf_install_local optional \
        unixODBC-devel

    dnf_install_local required \
        gdal-libs gdal-devel
        
    dnf_install_local required \
        protobuf
    dnf_install_local optional \
        protobuf-compiler protobuf-devel
    dnf_install_local required \
        protobuf-c protobuf-c-compiler
    dnf_install_local optional \
        protobuf-c-devel

    echo_success "基础依赖安装完成"
}

tune_os_for_postgresql() {
    echo_info "正在进行操作系统参数优化..."

    if command -v timedatectl >/dev/null 2>&1; then
        timedatectl set-timezone Asia/Shanghai || true
    fi

    if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
        setenforce 0 || true
        echo_warning "SELinux 已临时设为 Permissive"
    fi

    if [ -f /etc/selinux/config ]; then
        sed -ri 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config || true
        echo_warning "SELinux 已配置为永久禁用(需重启生效)"
    fi

    if command -v swapoff >/dev/null 2>&1; then
        swapoff -a || true
    fi

    local mem_kb page_size shmmax shmall
    mem_kb=$(grep -i '^MemTotal:' /proc/meminfo | awk '{print $2}')
    page_size=$(getconf PAGE_SIZE 2>/dev/null || echo 4096)
    if [ -n "$mem_kb" ] && [ -n "$page_size" ]; then
        shmmax=$((mem_kb*1024*75/100))
        shmall=$((shmmax/page_size))
    else
        shmmax=$((8*1024*1024*1024))
        shmall=$((shmmax/4096))
    fi

    cat > /etc/sysctl.d/postgresql-tuning.conf <<EOF
vm.overcommit_memory = 1
vm.swappiness = 1
fs.file-max = 1000000
kernel.shmmax = ${shmmax}
kernel.shmall = ${shmall}
net.ipv4.ip_local_port_range = 1024 65000
net.core.rmem_default = 262144
net.core.rmem_max = 4194304
net.core.wmem_default = 262144
net.core.wmem_max = 4194304
EOF

    sysctl -p /etc/sysctl.d/postgresql-tuning.conf >/dev/null 2>&1 || true

    if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
        echo never > /sys/kernel/mm/transparent_hugepage/enabled || true
    fi

    if ! grep -q 'pam_limits.so' /etc/pam.d/login 2>/dev/null; then
        echo 'session required /usr/lib64/security/pam_limits.so' >> /etc/pam.d/login || true
        echo 'session required pam_limits.so' >> /etc/pam.d/login || true
    fi

    cat > /etc/security/limits.d/postgresql.conf <<EOF
postgres soft nproc 65536
postgres hard nproc 65536
postgres soft nofile 65536
postgres hard nofile 65536
EOF

    if [ -f /etc/rc.d/rc.local ]; then
        chmod +x /etc/rc.d/rc.local || true
        if ! grep -q 'transparent_hugepage' /etc/rc.d/rc.local; then
            echo 'echo never > /sys/kernel/mm/transparent_hugepage/enabled' >> /etc/rc.d/rc.local
        fi
    fi

    echo_success "操作系统参数优化完成"
}

# 创建安装目录
prepare_directories() {
    echo_info "正在创建安装目录和源码目录..."
    
    # 创建目录
    mkdir -p "$PREFIX_BASE"
    mkdir -p "$PREFIX_PG"
    mkdir -p "$PREFIX_DEPS"
    mkdir -p "$PG_DATA_DIR"
    mkdir -p "$SRC_DIR"
    mkdir -p "$DOWNLOAD_DIR/$OS_SHORT"
    
    # 创建 postgres 用户
    if ! id postgres &> /dev/null; then
        useradd -r -m -s /bin/bash postgres
    else
        PG_HOME_DIR=$(getent passwd postgres | awk -F: '{print $6}')
        if [ -z "$PG_HOME_DIR" ] || [ ! -d "$PG_HOME_DIR" ]; then
            PG_HOME_DIR="/home/postgres"
            mkdir -p "$PG_HOME_DIR"
            chown postgres:postgres "$PG_HOME_DIR"
        fi
    fi

    # htop 配置
    mkdir -p /root/.config/htop/
    touch /root/.config/htop/htoprc
    
    # 设置权限
    chown -R postgres:postgres "$PREFIX_BASE"
    chown -R postgres:postgres "$SRC_DIR"
    
    echo_success "目录准备完成"
}

# 获取离线包路径
get_offline_package() {
    local package_name=$1
    local base_dir=${2:-$DOWNLOAD_DIR}

    echo_info "正在检查 $package_name 的离线包..." >&2

    local candidates=(
        "$base_dir/$OS_SHORT/$package_name"
        "$base_dir/srctar/$package_name"
        "$base_dir/$package_name"
    )

    for cand in "${candidates[@]}"; do
        if [ -f "$cand" ]; then
            echo "$cand"
            return 0
        fi
    done

    echo_error "错误：未找到离线包 $package_name" >&2
    echo_info "已检查路径：$base_dir/$OS_SHORT/、$base_dir/srctar/、$base_dir/" >&2
    echo_info "所需文件：$package_name" >&2
    exit 1
}

# 解压源码包
extract_source() {
    local archive=$1
    local target_dir=$2
    mkdir -p "$target_dir"
    echo_info "正在解压 $(basename "$archive")..."
    
    case "$archive" in
        *.tar.gz)
            tar -xzf "$archive" -C "$target_dir"
            ;;
        *.tar.xz)
            tar -xJf "$archive" -C "$target_dir"
            ;;
        *.tar.bz2)
            tar -xjf "$archive" -C "$target_dir"
            ;;
        *.zip)
            unzip "$archive" -d "$target_dir"
            ;;
        *)
            echo_error "不支持的压缩格式: $archive"
            return 1
            ;;
    esac
    
    echo_success "解压完成"
}

# 安装 PostgreSQL
install_postgresql() {
    echo_info "开始安装 PostgreSQL ${PG_VERSION}..."
    
    PG_PACKAGE="postgresql-${PG_VERSION}.tar.bz2"
    PG_PATH=$(get_offline_package "$PG_PACKAGE" "$DOWNLOAD_DIR")
    extract_source "$PG_PATH" "$SRC_DIR"
    
    cd "$SRC_DIR/postgresql-${PG_VERSION}"
    
    export PATH="${PREFIX_DEPS}/bin:${PATH}"
    LIBS="${LIBS}"
    if ls /usr/lib64/libdns_sd.so* >/dev/null 2>&1 || pkg-config --exists avahi-compat-libdns_sd >/dev/null 2>&1; then
        LIBS="${LIBS} -ldns_sd"
    fi
    PYTHON_BIN="$(command -v python3 || echo)"
    CFLAGS="-I$PREFIX_DEPS/include" \
    LDFLAGS="-L$PREFIX_DEPS/lib -Wl,-rpath,$PREFIX_DEPS/lib" \
    LIBS="${LIBS}" \
    PYTHON="$PYTHON_BIN" \
    ./configure --prefix="$PREFIX_PG" \
                --with-openssl \
                --with-readline \
                --with-icu \
                --with-libxml \
                --with-bonjour \
                --with-gssapi \
                --with-ldap \
                --with-pam \
                --with-selinux \
                --with-python \
                || {
        echo_error "配置 PostgreSQL 失败"
        exit 1
    }
    
    # 编译
    make -j$(nproc) -C src all || {
        echo_error "编译 PostgreSQL 失败"
        exit 1
    }
    
    # 安装
    make -C src install || {
        echo_error "安装 PostgreSQL 失败"
        exit 1
    }
    
    make -C contrib install || {
        echo_error "安装 PostgreSQL contrib 失败"
        exit 1
    }

    echo_success "PostgreSQL ${PG_VERSION} 安装完成"
}

# 安装 PostGIS
install_postgis() {
    echo_info "开始安装 PostGIS ${POSTGIS_VERSION}..."
    
    POSTGIS_PACKAGE="postgis-${POSTGIS_VERSION}.tar.gz"
    POSTGIS_PATH=$(get_offline_package "$POSTGIS_PACKAGE" "$DOWNLOAD_DIR")
    extract_source "$POSTGIS_PATH" "$SRC_DIR"
    
    cd "$SRC_DIR/postgis-${POSTGIS_VERSION}"
    
    # 配置环境变量
    export PKG_CONFIG_PATH="${PREFIX_DEPS}/lib/pkgconfig:${PKG_CONFIG_PATH}"
    export PATH="${PREFIX_PG}/bin:${PREFIX_DEPS}/bin:${PATH}"
    PERL_BIN="$(command -v perl || echo)"
    
    # 配置 PostGIS
    GEOSCONFIG_BIN="$(command -v geos-config || echo ${PREFIX_DEPS}/bin/geos-config)"
    CFLAGS="-I$PREFIX_PG/include" \
    LDFLAGS="-L$PREFIX_PG/lib" \
    ./configure --prefix="$PREFIX_POSTGIS" \
                --with-pgconfig="$PREFIX_PG/bin/pg_config" \
                --with-geosconfig="$GEOSCONFIG_BIN" \
                --with-sfcgal \
                --with-raster \
                --with-topology \
                --without-gui \
                --without-interrupt-tests || {
        echo_error "配置 PostGIS 失败"
        exit 1
    }
    
    # 编译
    make -j$(nproc) PERL="$PERL_BIN" || {
        echo_error "编译 PostGIS 失败"
        exit 1
    }
    
    # 安装
    make install PERL="$PERL_BIN" || {
        echo_error "安装 PostGIS 失败"
        exit 1
    }
       
    echo_success "PostGIS ${POSTGIS_VERSION} 安装完成"
}

install_thirdparty_extensions() {
    echo_info "正在编译安装第三方扩展..."
    local exts=(pg_cron pg_repack pg_partman pg_stat_kcache pg_wait_sampling pg_qualstats pg_stat_monitor)
    for ext in "${exts[@]}"; do
        local tar=""
        shopt -s nullglob
        for pat in "${DOWNLOAD_DIR}/srctar/${ext}-"*.tar.* "${DOWNLOAD_DIR}/srctar/${ext}"*.tar.*; do
            if [ -f "$pat" ]; then
                tar="$pat"
                break
            fi
        done
        shopt -u nullglob
        if [ -z "$tar" ]; then
            continue
        fi
        extract_source "$tar" "$SRC_DIR"
        local dir=""
        for cand in "$SRC_DIR/${ext}"*; do
            if [ -d "$cand" ]; then
                dir="$cand"
                break
            fi
        done
        if [ -z "$dir" ]; then
            continue
        fi
        if [ "$ext" = "pg_stat_monitor" ]; then
            if [ -f "$dir/pg_stat_monitor.c" ]; then
                sed -i 's/%lld/%ld/g' "$dir/pg_stat_monitor.c" || true
            fi
            (cd "$dir" && CFLAGS="-Wno-format" make USE_PGXS=1 PG_CONFIG="$PREFIX_PG/bin/pg_config" && CFLAGS="-Wno-format" make USE_PGXS=1 PG_CONFIG="$PREFIX_PG/bin/pg_config" install) || echo_warning "扩展 ${ext} 安装失败"
        else
            (cd "$dir" && make USE_PGXS=1 PG_CONFIG="$PREFIX_PG/bin/pg_config" && make USE_PGXS=1 PG_CONFIG="$PREFIX_PG/bin/pg_config" install) || echo_warning "扩展 ${ext} 安装失败"
        fi
    done
    echo_success "第三方扩展处理完成"
}

# 配置动态库加载路径
configure_ldconfig() {
    echo_info "正在配置动态库加载路径..."
    
    cat > /etc/ld.so.conf.d/postgresql-custom.conf <<EOF
${PREFIX_DEPS}/lib
${PREFIX_PG}/lib
EOF
    
    ldconfig
    
    echo_success "动态库加载路径配置完成"
}

# 初始化 PostgreSQL 数据库
initialize_postgresql() {
    echo_info "正在初始化 PostgreSQL 数据库..."
    
    if [ -d "$PG_DATA_DIR" ] && [ "$(ls -A "$PG_DATA_DIR" 2>/dev/null)" ]; then
        echo_warning "数据目录 $PG_DATA_DIR 不为空，跳过初始化"
        return 0
    fi
    
    su - postgres -c "$PREFIX_PG/bin/initdb -D '$PG_DATA_DIR'"
    
    echo_success "PostgreSQL 数据库初始化完成"
}

# 配置 PostgreSQL
configure_postgresql() {
    echo_info "正在配置 PostgreSQL..."
    
    CONFIG_DIR="${INSTALLER_DIR}/config"
    if [ -d "$CONFIG_DIR" ] && [ -f "$CONFIG_DIR/postgresql.conf.template" ]; then
        cp "$CONFIG_DIR/postgresql.conf.template" "$PG_DATA_DIR/postgresql.conf"
    else
        echo_warning "配置模板不存在，修改默认配置"
        sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/g" "$PG_DATA_DIR/postgresql.conf"
        sed -i "s/#password_encryption = scram-sha-256/password_encryption = scram-sha-256/g" "$PG_DATA_DIR/postgresql.conf"
        echo "dynamic_library_path = '$PREFIX_PG/lib'" >> "$PG_DATA_DIR/postgresql.conf"
        echo "logging_collector = on" >> "$PG_DATA_DIR/postgresql.conf"
        echo "log_destination = 'stderr'" >> "$PG_DATA_DIR/postgresql.conf"
        echo "log_directory = 'log'" >> "$PG_DATA_DIR/postgresql.conf"
        echo "log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'" >> "$PG_DATA_DIR/postgresql.conf"
        echo "log_line_prefix = '%m [%p] %q%u@%d '" >> "$PG_DATA_DIR/postgresql.conf"
        echo "log_truncate_on_rotation = on" >> "$PG_DATA_DIR/postgresql.conf"
        echo "log_rotation_age = 1d" >> "$PG_DATA_DIR/postgresql.conf"
        echo "log_rotation_size = 0" >> "$PG_DATA_DIR/postgresql.conf"
    fi
    
    if [ -d "$CONFIG_DIR" ] && [ -f "$CONFIG_DIR/pg_hba.conf.template" ]; then
        cp "$CONFIG_DIR/pg_hba.conf.template" "$PG_DATA_DIR/pg_hba.conf"
    else
        echo_warning "认证模板不存在，修改默认配置"
        echo "host    all             all             0.0.0.0/0               scram-sha-256" >> "$PG_DATA_DIR/pg_hba.conf"
    fi

    mkdir -p "$PG_DATA_DIR/log" "$PG_DATA_DIR/pg_log"
    chown -R postgres:postgres "$PG_DATA_DIR/log" "$PG_DATA_DIR/pg_log"
    
    chown -R postgres:postgres "$PG_DATA_DIR"
    chmod 700 "$PG_DATA_DIR"
    
    echo_success "PostgreSQL 配置完成"
}

# 创建 systemd 服务文件
create_systemd_service() {
    echo_info "正在创建 systemd 服务文件..."
    
    cat > /usr/lib/systemd/system/postgresql-custom.service <<EOF
[Unit]
Description=PostgreSQL Custom Database Server
After=network.target

[Service]
Type=forking
User=postgres
Environment=PGDATA=${PG_DATA_DIR}
Environment=LD_LIBRARY_PATH=${PREFIX_DEPS}/lib:${PREFIX_PG}/lib:${PREFIX_PG}/lib/postgresql
RuntimeDirectory=postgresql
RuntimeDirectoryMode=0755
ExecStartPre=/bin/mkdir -p /var/run/postgresql
ExecStartPre=/bin/chown postgres:postgres /var/run/postgresql
ExecStart=${PREFIX_PG}/bin/pg_ctl start -D \${PGDATA} -s -o "-p 5432"
ExecStop=${PREFIX_PG}/bin/pg_ctl stop -D \${PGDATA} -s -m fast
ExecReload=${PREFIX_PG}/bin/pg_ctl reload -D \${PGDATA} -s

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    
    echo_success "systemd 服务文件创建完成"
}

# 启动 PostgreSQL 服务
start_postgresql() {
    echo_info "正在启动 PostgreSQL 服务..."
    
    systemctl start postgresql-custom
    systemctl enable postgresql-custom
    
    if systemctl is-active --quiet postgresql-custom; then
        echo_success "PostgreSQL 服务启动成功"
    else
        echo_error "PostgreSQL 服务启动失败，请检查日志"
        last_log_file=$(ls -t "${PG_DATA_DIR}/pg_log" 2>/dev/null | head -n 1)
        if [ -n "$last_log_file" ]; then
            echo_info "最近日志文件: ${PG_DATA_DIR}/pg_log/${last_log_file}"
            tail -n 200 "${PG_DATA_DIR}/pg_log/${last_log_file}" || true
        fi
        exit 1
    fi
}

wait_for_postgresql_ready() {
    local retries=60
    local i=0
    while [ $i -lt $retries ]; do
        if systemctl is-active --quiet postgresql-custom; then
            su - postgres -c "${PREFIX_PG}/bin/pg_isready -h /var/run/postgresql" >/dev/null 2>&1 && return 0
        fi
        sleep 1
        i=$((i+1))
    done
    return 1
}

# 配置环境变量
configure_environment() {
    echo_info "正在配置环境变量..."
    
cat > /etc/profile.d/postgresql-custom.sh <<EOF
# PostgreSQL Custom Environment Variables
export PATH=${PREFIX_PG}/bin:$PATH
export LD_LIBRARY_PATH=${PREFIX_DEPS}/lib:${PREFIX_PG}/lib:${PREFIX_PG}/lib/postgresql:$LD_LIBRARY_PATH
export PGDATA=${PG_DATA_DIR}
export PGHOST=/var/run/postgresql
EOF
    
    source /etc/profile.d/postgresql-custom.sh
    
    echo_success "环境变量配置完成"
}

# 启用 PostGIS 扩展
enable_postgis() {
    echo_info "正在配置 PostGIS 扩展..."
    
    sleep 5
    
    export PATH="${PREFIX_PG}/bin:$PATH"
    export LD_LIBRARY_PATH="${PREFIX_DEPS}/lib:${PREFIX_PG}/lib:$LD_LIBRARY_PATH"
    
    su - postgres -c "PGHOST=/var/run/postgresql $PREFIX_PG/bin/psql --no-password -c \"ALTER SYSTEM SET dynamic_library_path = '$PREFIX_PG/lib';\"" || true
    su - postgres -c "PGHOST=/var/run/postgresql $PREFIX_PG/bin/psql --no-password -c 'SELECT pg_reload_conf();'" || true
    su - postgres -c "PGHOST=/var/run/postgresql $PREFIX_PG/bin/psql --no-password -c \"LOAD 'plpgsql';\"" || true

    su - postgres -c "PGHOST=/var/run/postgresql $PREFIX_PG/bin/psql --no-password -c 'CREATE EXTENSION IF NOT EXISTS plpgsql;'" || true
    su - postgres -c "PGHOST=/var/run/postgresql $PREFIX_PG/bin/psql --no-password -c 'CREATE EXTENSION IF NOT EXISTS postgis;'"
    su - postgres -c "PGHOST=/var/run/postgresql $PREFIX_PG/bin/psql --no-password -c 'CREATE EXTENSION IF NOT EXISTS postgis_raster;'" || true
    su - postgres -c "PGHOST=/var/run/postgresql $PREFIX_PG/bin/psql --no-password -c 'CREATE EXTENSION IF NOT EXISTS postgis_topology;'" || true
    
    POSTGIS_VERSION=$(su - postgres -c "$PREFIX_PG/bin/psql -t -c 'SELECT postgis_version();' 2>/dev/null")
    if [ -n "$POSTGIS_VERSION" ]; then
    echo_success "PostGIS 配置完成，版本: $POSTGIS_VERSION"
    else
        echo_error "PostGIS 配置失败，请检查是否正确安装"
    fi
}

enable_plpython() {
    echo_info "正在启用 PL/Python3 扩展..."
    su - postgres -c "PGHOST=/var/run/postgresql $PREFIX_PG/bin/psql --no-password -c 'CREATE EXTENSION IF NOT EXISTS plpython3u;'" || {
        echo_warning "PL/Python3 扩展启用失败，请检查python3与plpython构建是否完成"
    }
    echo_success "PL/Python3 扩展启用完成"
}

enable_common_extensions() {
    echo_info "正在启用常用扩展..."
    
    PRELOADS=()
    for lib in pg_stat_statements pg_stat_kcache pg_wait_sampling pg_qualstats pg_stat_monitor pg_cron; do
        if [ -f "${PREFIX_PG}/lib/${lib}.so" ]; then
            PRELOADS+=("${lib}")
        fi
    done
    if [ ${#PRELOADS[@]} -gt 0 ]; then
        systemctl stop postgresql-custom || true
        sed -i "s/^#\s*shared_preload_libraries\s*=\s*/shared_preload_libraries = /" "${PG_DATA_DIR}/postgresql.conf" || true
        sed -i "s/^#\s*cron\.database_name\s*=\s*/cron.database_name = /" "${PG_DATA_DIR}/postgresql.conf" || true
        systemctl start postgresql-custom || true
        systemctl enable postgresql-custom || true
        if ! wait_for_postgresql_ready; then
            echo_error "数据库重启后未就绪，请检查 ${PG_DATA_DIR}/pg_log 下的最新日志"
            last_log_file=$(ls -t "${PG_DATA_DIR}/pg_log" 2>/dev/null | head -n 1)
            if [ -n "$last_log_file" ]; then
                echo_info "最近日志文件: ${PG_DATA_DIR}/pg_log/${last_log_file}"
                tail -n 200 "${PG_DATA_DIR}/pg_log/${last_log_file}" || true
            fi
            return 1
        fi
    fi

    for ext in pg_stat_statements pg_prewarm pg_repack pg_partman pg_cron pg_stat_kcache pg_wait_sampling pg_qualstats pg_stat_monitor; do
        if [ -f "${PREFIX_PG}/share/extension/${ext}.control" ]; then
            su - postgres -c "PGHOST=/var/run/postgresql $PREFIX_PG/bin/psql --no-password -c 'CREATE EXTENSION IF NOT EXISTS ${ext};'" || true
        fi
    done
    echo_success "常用扩展启用完成"
}

# 配置防火墙
configure_firewall() {
    echo_info "正在配置防火墙..."
    
    if command -v firewall-cmd &> /dev/null && firewall-cmd --state &> /dev/null; then
        firewall-cmd --permanent --add-port=5432/tcp
        firewall-cmd --reload
        echo_success "防火墙配置完成"
    else
        echo_warning "firewalld 未运行，跳过防火墙配置"
    fi
}

# 设置 PostgreSQL 密码
set_postgres_password() {
    echo_info "正在设置 PostgreSQL 密码..."
    su - postgres -c "PGHOST=/var/run/postgresql $PREFIX_PG/bin/psql --no-password -c \"ALTER USER postgres WITH PASSWORD '$PG_PASSWORD';\""
    
    echo_success "PostgreSQL 密码设置完成"
}

# 清理临时文件
cleanup() {
    echo_info "正在清理临时文件..."
    
    rm -rf "$SRC_DIR"
    
    echo_success "清理完成"
}

# 显示安装信息
display_info() {
    echo_success "\n======================================="
    echo_success "PostgreSQL ${PG_VERSION} 和 PostGIS ${POSTGIS_VERSION} 编译安装完成！"
    echo_success "======================================="
    echo_info "安装目录: $PREFIX_PG"
    echo_info "数据目录: $PG_DATA_DIR"
    echo_info "依赖目录: $PREFIX_DEPS"
    echo_info "服务名称: postgresql-custom"
    echo_info "端口: 5432"
    echo_info ""
    echo_info "连接命令: $PREFIX_PG/bin/psql -U postgres -h localhost"
    echo_info "服务控制: systemctl [start|stop|restart|status] postgresql-custom"
    echo_info ""
    echo_warning "注意：请重新登录或执行 'source /etc/profile.d/postgresql-custom.sh' 以加载环境变量"
    echo_success "======================================="
}

# 主函数
main() {
    echo_info "开始编译安装 PostgreSQL ${PG_VERSION} 和 PostGIS ${POSTGIS_VERSION} ..."
    
    check_root
    detect_os
    prepare_directories
    tune_os_for_postgresql
    install_system_deps
    install_postgresql
    install_postgis
    install_thirdparty_extensions
    configure_ldconfig
    initialize_postgresql
    configure_postgresql
    create_systemd_service
    start_postgresql
    configure_environment
    set_postgres_password
    enable_postgis
    enable_plpython
    enable_common_extensions
    configure_firewall
    cleanup
    display_info
}

# 执行主函数
main