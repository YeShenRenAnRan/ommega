MODDIR=${0%/*}
TARGET_DIR=/data/misc/keystore/ommega
LOG_DIR=$TARGET_DIR/logs
LOG_FILE=$LOG_DIR/post-fs-data.log
# app 域（SOTER 宿主 uid 1000）进不去 keystore 那个 0770 目录，payload 的日志
# 得有个它写得动的位置：权限开到 system 组。
APP_LOG_DIR=/data/misc/ommega/logs
TARGET_KEYBOX=$TARGET_DIR/keybox.xml
TARGET_INJECTOR_CONFIG=$TARGET_DIR/injector.toml
TARGET_CONF=$TARGET_DIR/config
TARGET_TARGET_LIST=$TARGET_DIR/target.txt
STATE_DIR=/data/adb/ommega
BIN_DIR=$STATE_DIR/bin
CONF_DIR=$STATE_DIR/conf
RUN_DIR=$STATE_DIR/run
DB_DIR=$STATE_DIR/db
[ -f "$MODDIR/layout.sh" ] && . "$MODDIR/layout.sh" 2>/dev/null
# A-side config directory (webroot UI writes here; `ommegadata` is a symlink to
# $TARGET_DIR, so the UI and the keystore process (uid 1017) share one copy).
CLIENTA_DIR=/data/adb/ommega

# 系统属性伪装用模块**自己带**的 resetprop（实现是 vendor/ 里的 resetprop-rs；
# customize.sh 安装时会把与设备 ABI 匹配的那份拷到状态目录）。以前靠管理器提供：
# Magisk 自带、APatch/KSU 走 busybox/ksud，不是每家都有、行为也不一致，所以不再依赖。
# 定成同名函数，下面那一串调用一字不用改；实在找不到自己的才退回 PATH 里那个。
RESETPROP_BIN=$BIN_DIR/resetprop
if [ ! -x "$RESETPROP_BIN" ]; then
  rp_abi=$(getprop ro.product.cpu.abi 2>/dev/null)
  case "$rp_abi" in
    arm64*) rp_abi=arm64-v8a ;;
    armeabi*|armv7*) rp_abi=armeabi-v7a ;;
    x86_64*) rp_abi=x86_64 ;;
    i?86|x86) rp_abi=x86 ;;
    *) rp_abi= ;;
  esac
  if [ -n "$rp_abi" ] && [ -x "$MODDIR/libs/$rp_abi/resetprop" ]; then
    RESETPROP_BIN="$MODDIR/libs/$rp_abi/resetprop"
  else
    RESETPROP_BIN=resetprop
  fi
  unset rp_abi
fi
resetprop() { "$RESETPROP_BIN" "$@"; }

# persist.* 要带 -p：不带的话只改内存属性区，init 落在 /data/property/ 的那份镜像
# 不会跟着变，两边一对就露（检测项 device.property.persistent_suspicious）。
resetprop -p persist.logd.size ""
resetprop -p persist.logd.size.crash ""
resetprop -p persist.logd.size.system ""
resetprop -p persist.logd.size.main ""
resetprop ro.boot.flash.locked 1
resetprop ro.boot.verifiedbootstate green
resetprop ro.boot.veritymode enforcing
resetprop ro.boot.vbmeta.device_state locked
resetprop ro.secure 1
resetprop ro.adb.secure 1
resetprop ro.debuggable 0
resetprop sys.oem_unlock_allowed ""
resetprop ro.secureboot.devicelock 1

# 开机时就把 B 真机声明的身份对齐到本机（文件由 TA 在远程出链时写入）：
# 链是真机出的，本机属性必须说同一台机器，否则检测器报 device_properties /
# VBMeta 摘要不一致。daemon 运行期也会再同步一次（带 zygote 软重启）。
_OMMEGA_IDENTITY=/data/misc/keystore/ommega/remote_identity
if [ -f "$_OMMEGA_IDENTITY" ]; then
  _id_set() {
    [ -n "$1" ] && [ -n "$2" ] && resetprop "$1" "$2"
  }
  _id_get() { sed -n "s/^$1=//p" "$_OMMEGA_IDENTITY" 2>/dev/null | head -n1; }
  _id_set ro.product.brand "$(_id_get brand)"
  _id_set ro.product.device "$(_id_get device)"
  _id_set ro.product.name "$(_id_get product)"
  _id_set ro.product.manufacturer "$(_id_get manufacturer)"
  _id_set ro.product.model "$(_id_get model)"
  _id_set ro.serialno "$(_id_get serial)"
  _id_set ro.boot.vbmeta.digest "$(_id_get vbmeta_digest)"
fi
mkdir -p "$TARGET_DIR"
chmod 0770 "$TARGET_DIR"
chown 1017:1017 "$TARGET_DIR"
# 「启用调试日志」关着时不要建任何日志目录：以前无条件 mkdir，用户关着日志也会
# 多出两个空空的 logs 目录。真正的写日志在 `log_line` 里还要再判一次。
debug_logging_enabled() {
  [ -f "$TARGET_CONF" ] || return 1
  val=$(sed -n 's/^[[:space:]]*\(debug_logging\|debug\|verbose\)[[:space:]]*:[[:space:]]*\(.*\)$/\2/p' "$TARGET_CONF" 2>/dev/null | head -n1 | tr -d ' \r' | tr 'A-Z' 'a-z')
  case "$val" in
    1|true|yes|on) return 0 ;;
  esac
  return 1
}
if debug_logging_enabled; then
  mkdir -p "$LOG_DIR"
  chmod 0770 "$LOG_DIR"
  chown 1017:1017 "$LOG_DIR"
  mkdir -p "$APP_LOG_DIR"
  chmod 0770 "$APP_LOG_DIR"
  chown 0:1000 "$APP_LOG_DIR"
fi
mkdir -p "$STATE_DIR"
rm -f "$RUN_DIR/keymint-daemon.pid" "$RUN_DIR/injector-daemon.pid"

# 只落文件，不再往 stdout 打（那会进管理器的日志，也是系统日志）。
log_line() {
  debug_logging_enabled || return 0
  mkdir -p "$LOG_DIR" 2>/dev/null
  printf '%s [INFO] %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE" 2>/dev/null
  return 0
}
rm -f "$RUN_DIR/restart.keymint" "$RUN_DIR/restart.injector" "$RUN_DIR/restart.all"

# Make the shared A-side config directory traversable and expose the data dir.
mkdir -p "$CLIENTA_DIR"
chmod 0755 "$CLIENTA_DIR"
# The webroot UI and the keystore process (uid 1017) must share ONE data dir:
# the UI only writes "$CLIENTA_DIR/ommegadata/*", the daemons only read
# "$TARGET_DIR/*".  A plain directory (or file) left at that path by an older
# build, a manual step or a file manager puts both sides on separate copies —
# UI saves would then silently never reach the daemon.  Repair it every boot:
# migrate what is there, then replace it with the symlink.
if [ -L "$CLIENTA_DIR/ommegadata" ]; then
  : # already the symlink
elif [ -d "$CLIENTA_DIR/ommegadata" ]; then
  for f in config target.txt system_app keybox.xml; do
    stray="$CLIENTA_DIR/ommegadata/$f"
    real="$TARGET_DIR/$f"
    [ -f "$stray" ] || continue
    # Newest copy wins; copy in place so owner/mode of the real file survive.
    if [ ! -f "$real" ] || [ "$stray" -nt "$real" ]; then
      cat "$stray" > "$real" 2>/dev/null || true
    fi
  done
  rm -rf "$CLIENTA_DIR/ommegadata"
  ln -s "$TARGET_DIR" "$CLIENTA_DIR/ommegadata" 2>/dev/null
elif [ -e "$CLIENTA_DIR/ommegadata" ]; then
  # Stray regular file: keep it aside, then expose the real dir as a symlink.
  mv -f "$CLIENTA_DIR/ommegadata" "$CLIENTA_DIR/ommegadata.stray" 2>/dev/null
  ln -s "$TARGET_DIR" "$CLIENTA_DIR/ommegadata" 2>/dev/null
else
  ln -s "$TARGET_DIR" "$CLIENTA_DIR/ommegadata" 2>/dev/null
fi

# Single data location for the flat A-side config and per-app target list.
# The webroot UI writes these through the `ommegadata` symlink, so no copy is
# needed.  Seed the config on first install with the official online service
# defaults (README "快速使用（官方在线服务）"), so the A-side connects out of
# the box; an already-present config (e.g. from the WebUI or a previous install)
# is left untouched.
if [ ! -f "$TARGET_CONF" ]; then
  cat > "$TARGET_CONF" <<'EOF'
url: http://110.40.170.96:10886
token: aY7kRSDDR6PMmamlKwtgf7mQgr-X5uFd
# device_id 故意留空：留空 = 「让服务端挑一台 B」。服务端用后台配的「默认设备 id」，
# 没配就按负载挑一台在线的（keymint 有效、已锁定、可信启动）。
# 不再像以前那样占位一个 device-b-2：那个名字是服务端公开密钥库的专用槽位，
# 不是一台真 B，填进去只会把请求钉到一个不该去的地方。
# 想固定落到某一台就手动填，或者在 WebUI 的「伪装参数」里点「从服务端同步并保存」。
device_id:
tls_insecure: true
remote: on
EOF
fi
if [ ! -f "$TARGET_TARGET_LIST" ]; then
  : > "$TARGET_TARGET_LIST"
fi
chmod 0644 "$TARGET_CONF" "$TARGET_TARGET_LIST" 2>/dev/null || true
chown 1017:1017 "$TARGET_CONF" "$TARGET_TARGET_LIST" 2>/dev/null || true

# Keybox: the webroot UI writes `/data/adb/ommega/ommegadata/keybox.xml` which IS
# $TARGET_KEYBOX (via symlink).  Seed from the module keybox if absent.
if [ ! -f "$TARGET_KEYBOX" ] && [ -f "$MODDIR/keybox.xml" ]; then
  cp "$MODDIR/keybox.xml" "$TARGET_KEYBOX"
fi

if [ ! -f "$TARGET_INJECTOR_CONFIG" ] && [ -f "$MODDIR/injector.toml" ]; then
  cp "$MODDIR/injector.toml" "$TARGET_INJECTOR_CONFIG"
fi

if [ -f "$TARGET_KEYBOX" ]; then
  chmod 0600 "$TARGET_KEYBOX"
  chown 1017:1017 "$TARGET_KEYBOX"
fi

if [ -f "$TARGET_INJECTOR_CONFIG" ]; then
  chmod 0600 "$TARGET_INJECTOR_CONFIG"
  chown 1017:1017 "$TARGET_INJECTOR_CONFIG"
fi

# ---- 开机期声明（config.toml 的 [trust]）----
# 检测类 App 比对的是「链里的补丁 tag ↔ 设备属性」，而属性区是 init 开机时加载的：
# 等 zygote/框架起来之后再写运行时属性，已 fork 出去的进程看不到（实测运行期
# resetprop 改不动 App 的 SPL 视图）。所以显式声明必须在这一阶段写进属性区。
# 运行期那条路（daemon 启动时写）保留，管的是我们自己铸链用的 ctx。
# 只有显式写了值才动；auto 一律保持设备原值。
DECLARED_CONF=$TARGET_DIR/config.toml
# 只在设备本来就有这个属性时才改。
#
# 凭空造一个新属性比不改更糟：检测器一看「这型号怎么会有这个键」就露了，
# 而且 resetprop 造出来的值也不会被所有读取方认。所以凡是「改」都先确认真有；
# 没有就跳过，让链上那份自己去算。
setprop_if_present() {
  [ -n "$(getprop "$1" 2>/dev/null)" ] || return 0
  resetprop "$1" "$2"
}

if [ -f "$DECLARED_CONF" ]; then
  # cfg_val <key>：取 config.toml 里 "key = \"value\"" 的 value（[trust] 下的键）
  cfg_val() {
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"\([^\"]*\)\".*$/\1/p" "$DECLARED_CONF" 2>/dev/null | head -n1 | tr -d '\r'
  }
  d_patch=$(cfg_val security_patch)
  # 没单写就跟着 security_patch 走，跟 Rust 侧 resolve_patch_levels 的继承顺序一致
  d_os=$(cfg_val os_patchlevel); [ "$d_os" = auto ] && d_os=$d_patch
  d_vendor=$(cfg_val vendor_patchlevel); [ "$d_vendor" = auto ] && d_vendor=$d_patch
  # boot 不继承，也不推导：设备原本没这个属性就不造（凭空造一个反而多一处马脚）。
  # 链上的 boot 补丁级别由 keymint 运行时按 boot 镜像日期算，不靠这个属性。
  d_boot=$(cfg_val boot_patchlevel)
  for pair in "$d_os|ro.build.version.security_patch" "$d_vendor|ro.vendor.build.security_patch" "$d_boot|ro.vendor.boot_security_patch"; do
    value=${pair%%|*}
    prop=${pair##*|}
    case "$value" in ""|auto) continue ;; esac
    setprop_if_present "$prop" "$value"
    log_line "ommega: declared $prop=$value (boot stage)"
  done
  # 引导器锁定状态：不少检测器会看。只有真的存在这个键的机型才改。
  setprop_if_present ro.secureboot.lockstate locked
  d_vbkey=$(cfg_val vb_key)
  case "$d_vbkey" in ""|auto|random) ;; *) setprop_if_present ro.boot.vbmeta.public_key_digest "$d_vbkey"; log_line "ommega: declared vbmeta key (boot stage)" ;; esac
  d_vbhash=$(cfg_val vb_hash)
  case "$d_vbhash" in ""|auto|random) ;; *) setprop_if_present ro.boot.vbmeta.digest "$d_vbhash"; log_line "ommega: declared vbmeta hash (boot stage)" ;; esac
  unset d_patch d_os d_vendor d_boot d_vbkey d_vbhash
fi

# ---- 面板里设的属性覆盖 ----
# 单独存一份（$CONF_DIR/props.conf），**不写进这个脚本**：模块一升级，这个脚本
# 就被新版本整个替掉，写在里面的设置会跟着没（以前就是这么丢的）。
#
# 放在最后应用：它是用户在面板上明确点的，优先级高于上面那套默认值和 config.toml
# 里的开机期声明。一行一项 `键: 值`；值可以带引号，不带空格；**空值 = 不覆盖**
# （那一项就由模块自己的默认值决定）。
PROP_OVERRIDES=$CONF_DIR/props.conf
if [ -r "$PROP_OVERRIDES" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    p_key=${line%%:*}
    p_val=${line#*:}
    p_key=$(printf '%s' "$p_key" | tr -d ' \t\r')
    p_val=$(printf '%s' "$p_val" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    # 值两边手写的引号去掉（面板不写引号，但手改文件可能会带）
    case "$p_val" in
      \"*\") p_val=${p_val#\"}; p_val=${p_val%\"} ;;
    esac
    case "$p_key" in
      ro.*|persist.*|sys.*) : ;;
      *) continue ;;
    esac
    [ -n "$p_val" ] || continue
    setprop_if_present "$p_key" "$p_val"
    log_line "ommega: override $p_key=$p_val (boot stage)"
  done < "$PROP_OVERRIDES"
fi

# ---- 能力声明隐藏（flat config 键 hide_strongbox / hide_device_ids）----
# 挂载完全交给 root 管理器（Magisk magic mount / KernelSU overlayfs）：
# customize.sh 安装时按设备实际情况在模块 system/<分区>/etc/permissions/ 下
# 放置了 0:0 dummy 设备（whiteout），管理器开机挂载时据此删掉对应的 feature
# XML，PackageManager 即报不支持；keystore 守护进程（Rust 侧）读同一开关决定
# 是否注册 STRONGBOX security level（config watcher 热生效）。这里只按开关
# 增删标记文件，改动下次重启生效。
#
# 两个开关共用这套机制：
#   hide_strongbox   → android.hardware.security.strongbox_keystore.xml
#   hide_device_ids  → android.software.device_id_attestation.xml
# 后者声明「不支持 ID 认证」之后，应用/检测器会整体跳过设备 ID 证明（而不是每笔
# 都回 CannotAttestIds），也就不需要再把本机型号/品牌同步成远端那台机器。
WL_RELS="vendor/etc/permissions product/etc/permissions system_ext/etc/permissions etc/permissions"

# mask_feature <feature xml 文件名> <配置键...>
mask_feature() {
  mf_name=$1
  shift
  mf_enabled=false
  if [ -f "$TARGET_CONF" ]; then
    mf_pat=$(printf '%s|' "$@")
    mf_pat=${mf_pat%|}
    mf_value=$(grep -iE "^[[:space:]]*(${mf_pat})[[:space:]]*:" "$TARGET_CONF" 2>/dev/null | head -n 1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    case "$mf_value" in
      1|true|yes|on) mf_enabled=true ;;
      0|false|no|off) mf_enabled=false ;;
      # 没写这个键时看调用方的默认值：device_id 那一项默认关，strongbox 默认关。
      *) [ "${OMMEGA_MASK_DEFAULT:-0}" = "1" ] && mf_enabled=true ;;
    esac
  fi
  for mf_rel in $WL_RELS; do
    mf_marker="$MODDIR/system/$mf_rel/$mf_name"
    # 换算回系统里的真实路径：vendor 那种自带分区前缀，system 的要补上
    case "$mf_rel" in
      vendor/*|product/*|system_ext/*) mf_src="/$mf_rel/$mf_name" ;;
      *) mf_src="/system/$mf_rel/$mf_name" ;;
    esac
    if [ "$mf_enabled" = true ]; then
      # 系统里真实存在声明、且模块还没有标记时补建（覆盖安装后才出现声明、
      # 或曾被关闭删掉的情形）；设备上不存在的分区路径自然跳过，零副作用
      [ -f "$mf_src" ] || continue
      [ -e "$mf_marker" ] && continue
      mkdir -p "$MODDIR/system/$mf_rel"
      if mknod "$mf_marker" c 0 0 2>/dev/null; then
        log_line "ommega: $mf_name hidden; whiteout restored at $mf_rel"
      elif printf '<?xml version="1.0" encoding="utf-8"?>\n<permissions/>\n' > "$mf_marker" 2>/dev/null; then
        log_line "ommega: $mf_name hidden; overlay restored at $mf_rel"
      fi
    elif [ -e "$mf_marker" ]; then
      rm -f "$mf_marker"
      log_line "ommega: $mf_name shown again; marker removed from $mf_rel"
    fi
  done

  # 挂载层的兜底：管理器没给这个分区做 overlay（这台 KernelSU 3.3 就只覆盖 /system，
  # `/vendor` 是独立 erofs、`/system/vendor` 只是软链）—— 那 whiteout 白种了。
  # 不再把 /data 里的文件 bind 到 /vendor 的那个 XML 上：那条挂载在 mountinfo 里长
  # 这样 `... /adb/ommega/empty_permissions.xml /vendor/etc/permissions/xxx.xml ...
  # f2fs`，连源路径都写着，用户态一眼看出来。这里改成：先在 /mnt/vendor/ 下挂一个
  # 小 tmpfs（看起来像 OEM 自己挂的），里面放一个空 `<permissions/>`，再把这个
  # **单文件** bind 到真实 XML 上。
  #
  # 只盖这一个文件，**绝不动目录**：早先试过把整目录 bind 成暂存副本，结果那个
  # 暂存目录的目录标签/挂载参数跟 system_server 期望的不一致，PackageManager 读不
  # 到权限 XML，框架直接起不来、卡开机。一个文件被盖，旁边 59 个 XML 还是原样。
  if [ "$mf_enabled" = true ]; then
    mf_fake_base=${OMMEGA_FAKE_MOUNT_BASE:-/mnt/vendor/vendor_permissions}
    for mf_rel in $WL_RELS; do
      case "$mf_rel" in
        vendor/*|product/*|system_ext/*) mf_src="/$mf_rel/$mf_name" ;;
        *) mf_src="/system/$mf_rel/$mf_name" ;;
      esac
      mf_dir=$(dirname "$mf_src")
      [ -f "$mf_src" ] || continue
      # overlay 真生效时这里已经是 whiteout 设备或空声明，不用再盖
      grep -q '<permissions/>' "$mf_src" 2>/dev/null && continue
      grep -q " $mf_src " /proc/mounts 2>/dev/null && continue

      if ! grep -q " $mf_fake_base " /proc/mounts 2>/dev/null; then
        mkdir -p "$mf_fake_base" 2>/dev/null
        mount -t tmpfs -o mode=0755,seclabel tmpfs "$mf_fake_base" 2>/dev/null || {
          log_line "ommega: tmpfs mount for $mf_fake_base failed; mask skipped"
          continue
        }
      fi
      # 暂存文件名别把目标写进去：mountinfo 里会原样显示挂载根的路径，
      # 写 `_vendor_etc_permissions_android.software.device_id_attestation.xml`
      # 等于自己把“我遮了哪个文件”写在脸上。
      mf_stage="$mf_fake_base/vendor.conf"
      printf '<?xml version="1.0" encoding="utf-8"?>\n<permissions/>\n' > "$mf_stage" 2>/dev/null || continue
      chmod 0644 "$mf_stage" 2>/dev/null
      case "$mf_src" in
        /vendor/*) chcon u:object_r:vendor_file:s0 "$mf_stage" 2>/dev/null ;;
        *) chcon u:object_r:system_file:s0 "$mf_stage" 2>/dev/null ;;
      esac
      if mount --bind "$mf_stage" "$mf_src" 2>/dev/null; then
        # 不再 remount,ro：那个 ro 只会落在其中一个挂载命名空间（init 这份），
        # 而 shared:43 传播出去的另一份还是 rw —— 结果是同一个文件在不同进程的
        # mountinfo 里一个 ro 一个 rw，DuckDetector 的「跨进程视图对比」正好拿这个
        # 当“选择性隐藏”报出来（2026-10-23 实测：两份签名，分属 325 / 623 个进程）。
        # 而它真正会报的 “System RW” 只判 target 完全等于 /vendor 的挂载，
        # 文件级 bind 根本不在那条规则里，所以 ro 没赚到任何东西。
        log_line "ommega: $mf_name masked by $mf_stage over $mf_src"
      else
        log_line "ommega: bind for $mf_src failed; feature stays visible"
      fi
    done
  fi
}

OMMEGA_MASK_DEFAULT=0 mask_feature android.hardware.security.strongbox_keystore.xml hide_strongbox no_strongbox hide_strongbox_keystore
OMMEGA_MASK_DEFAULT=0 mask_feature android.software.device_id_attestation.xml hide_device_ids no_device_ids hide_device_id_attestation
unset WL_RELS mf_name mf_enabled mf_pat mf_value mf_rel mf_marker mf_src

# ── 尽早把两个守护拉起来 ─────────────────────────────────────────────────
# 为什么抢在 post-fs-data（最早那个阶段）而不是 service.sh（late_start）：注入 keystore2
# 越早越好 —— 框架的 `onDeviceUnlocked` 只在解锁那一刻发一次、从不补发；那会儿我们还没
# 进 keystore2 的话，这份解锁材料就永久丢了，影子 keystore 会一直 LOCKED 到下一次解锁。
# service.sh 里还有一份同样的启动（这里失败/被杀就靠它兑底），它会先看这两个 pid 文件，
# 活着就不重复启。
pid_matches_script() {
  p=$1
  s=$2
  [ -r "/proc/$p/cmdline" ] || return 1
  tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -F "$s" >/dev/null 2>&1
}

start_daemon_early() {
  script=$1
  pidfile=$2
  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && pid_matches_script "$pid" "$script"; then
      return 0
    fi
    rm -f "$pidfile"
  fi
  # 离开 post-fs-data 阶段后子进程可能被收走，所以用 setsid 脱开（没有就退回普通后台）。
  if command -v setsid >/dev/null 2>&1; then
    setsid sh "$script" >/dev/null 2>&1 &
  else
    sh "$script" >/dev/null 2>&1 &
  fi
  pid=$!
  echo $pid > "$pidfile"
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null || ! pid_matches_script "$pid" "$script"; then
    rm -f "$pidfile"
    return 1
  fi
  return 0
}

if [ -f "$MODDIR/daemon" ]; then
  if start_daemon_early "$MODDIR/daemon" "$RUN_DIR/keymint-daemon.pid"; then
    log_line "ommega: keymint daemon started early in post-fs-data"
  else
    log_line "ommega: keymint daemon early start failed; service.sh will retry"
  fi
fi
if [ -f "$MODDIR/daemon-injector" ]; then
  if start_daemon_early "$MODDIR/daemon-injector" "$RUN_DIR/injector-daemon.pid"; then
    log_line "ommega: injector daemon started early in post-fs-data"
  else
    log_line "ommega: injector daemon early start failed; service.sh will retry"
  fi
fi
