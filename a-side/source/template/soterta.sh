#!/system/bin/sh
# 软件 SOTER TA 的开关与守护。
#
# 原厂 `vendor.qti.hardware.soter.ISoter/default` 只是 TEE 里那个 applet 的薄代理，
# applet 起不来时整族调用一律 -20（一加 PKG110 / 安卓15 实测），微信、以及产线工具
# （工程模式那页的 SOTER key）一起哑。接管的意思是：把 init 的原厂 HAL 停掉，由
# `ommega-inject --soterta-serve` 顶上同一个服务名，用我们自己的 ASK 应答。
#
#   soterta.sh             converge 一次（service.sh 每轮调）
#   soterta.sh status      打一行状态
#
# 开关在 /data/misc/keystore/ommega/config 的 `soter_inject`（1/0），WebUI 写。
# 关掉就是「原厂 HAL 回来」：杀我们的守护、ctl.start vendor.soter。
#
# 为什么不用注入：soterserver 在这个机型上是 platform_app 域 + 它的 libbinder 带共享
# 映射，lsplt 一个 GOT 都认不下来（commit 全失败）。接管服务名跟注入无关，客户端
# 一行都不用改。

MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega
CONF=${OMMEGA_CONF_PATH:-/data/misc/keystore/ommega/config}
PIDFILE=$STATE_DIR/soterta.pid
KICKED_FILE=$STATE_DIR/soterta.host.kicked
# 最后一次踢宿主时对应的 TA 实例（pid）。换实例就要重踢，见 kick_host。
TAKEOVER_PID=$STATE_DIR/soterta.takeover.pid
LOG=$STATE_DIR/logs/soterta.log
SERVICE=vendor.qti.hardware.soter.ISoter/default
HAL=vendor.soter
BIN=

log() {
  mkdir -p "$STATE_DIR/logs" 2>/dev/null
  printf '%s %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG" 2>/dev/null
}

conf_get() {
  [ -f "$CONF" ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*:[[:space:]]*\(.*\)$/\1/p" "$CONF" 2>/dev/null | head -n1
}

enabled() {
  case "$(conf_get soter_inject | tr 'A-Z' 'a-z' | tr -d ' \r')" in
    1|true|yes|on) return 0 ;;
  esac
  return 1
}

device_abi() {
  abi=$(getprop ro.product.cpu.abi 2>/dev/null)
  case "$abi" in
    arm64*|aarch64*) echo arm64-v8a ;;
    armeabi*|armv7*) echo armeabi-v7a ;;
    x86_64*) echo x86_64 ;;
    i?86|x86) echo x86 ;;
    *) echo "" ;;
  esac
}

find_bin() {
  [ -n "$BIN" ] && return 0
  for candidate in "$STATE_DIR/ommega-inject" "$MODDIR/ommega-inject"; do
    if [ -x "$candidate" ]; then BIN=$candidate; return 0; fi
  done
  abi=$(device_abi)
  if [ -n "$abi" ] && [ -x "$MODDIR/libs/$abi/ommega-inject" ]; then
    BIN=$MODDIR/libs/$abi/ommega-inject
    return 0
  fi
  return 1
}

# daemon-injector 每轮注入前会 `pkill -9 -f "$TARGET_INJECTOR"` 清残留，而它的
# TARGET_INJECTOR 跟我们的宿主同名。宿主直接用那个路径就会被连带杀掉（实测每 20 秒
# 一轮），服务名反复重建、宿主握不住，App 一调就是系统错误。
# 拷一份到独立文件名，离开那条 pkill 的匹配。
stage_bin() {
  [ -n "$BIN" ] || return 1
  dst="$STATE_DIR/soterta-ta"
  if [ ! -x "$dst" ] || ! cmp -s "$BIN" "$dst" 2>/dev/null; then
    cp -f "$BIN" "$dst.tmp" 2>/dev/null && chmod 755 "$dst.tmp" && mv -f "$dst.tmp" "$dst"
  fi
  [ -x "$dst" ] && BIN=$dst
  return 0
}

hal_state() {
  value=$(getprop "init.svc.$HAL" 2>/dev/null)
  [ -n "$value" ] && echo "$value" || echo unknown
}

service_present() {
  service check "$SERVICE" 2>/dev/null | grep -q ': found$'
}

daemon_pid() {
  [ -f "$PIDFILE" ] || return 1
  pid=$(cat "$PIDFILE" 2>/dev/null)
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  kill -0 "$pid" 2>/dev/null || return 1
  tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q 'soterta-serve' || return 1
  echo "$pid"
}

stop_daemon() {
  pid=$(daemon_pid)
  if [ -n "$pid" ]; then
    kill -TERM "$pid" 2>/dev/null
    i=0
    while [ "$i" -lt 10 ] && kill -0 "$pid" 2>/dev/null; do
      sleep 0.3
      i=$((i + 1))
    done
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null
  fi
  rm -f "$PIDFILE" 2>/dev/null
}

# 抢服务名：先把原厂 HAL 停了（不停的话 servicemanager 那边名字还是它的），再起
# 我们的守护。启动失败就退回去把原厂 HAL 拉起来，不能把整台机的 SOTER 留成死的。
take_over() {
  find_bin || { log "injector binary not found"; return 1; }
  stage_bin
  # 服务名只有一个 owner：原厂 HAL 还在跑的时候我们注册不上去（servicemanager 直接拒），
  # 所以**先停原厂、再起守护**。顺序反过来的话每一轮都是「起守护→注册失败→停原厂→
  # 再查服务名→没有→判 takeover failed→拉回原厂」（2026-10-20 PKX110 上实测空转 1507 次）。
  if [ "$(hal_state)" = "running" ]; then
    log "stopping stock SOTER HAL"
    setprop ctl.stop "$HAL" 2>/dev/null
    sleep 1
  fi
  if [ -z "$(daemon_pid)" ]; then
    start_daemon
  elif ! service_present; then
    # 守护还活着但手上没有服务名：它是在原厂占着名字的时候起来的，重起一个再试。
    log "software SOTER TA is up but holds no service name; restarting it"
    start_daemon restart
  fi
  if [ -z "$(daemon_pid)" ] || ! service_present; then
    log "takeover failed, restoring stock HAL"
    stop_daemon
    setprop ctl.start "$HAL" 2>/dev/null
    return 1
  fi
  # 宿主（soterserver）把 HAL 代理缓存在 static 字段里，我们一换服务实例那份代理就死了，
  # 但它不会自己重查 —— App 一调就 DeadObjectException（微信直接「系统错误」，而日志里
  # 一笔 HAL 调用都看不到）。详见 kick_host。
  kick_host
  return 0
}

# 起守护并等它把服务名注册上。`restart` 表示先收掉旧的那个。
start_daemon() {
  if [ "$1" = "restart" ]; then
    stop_daemon
  fi
  log "starting software SOTER TA: $BIN"
  "$BIN" --soterta-serve >>"$LOG" 2>&1 &
  pid=$!
  echo "$pid" > "$PIDFILE.tmp" 2>/dev/null
  mv -f "$PIDFILE.tmp" "$PIDFILE" 2>/dev/null
  sleep 1
}

# 宿主手里缓存的是旧服务实例的代理，**每换一次 TA 实例就得踢一次**。
#
# 所以记的是「踢过哪个 TA 实例」（$TAKEOVER_PID 里存那次的 pid），而不是「踢过一次没有」：
# 旧的那套 `soterta.host.kicked` 只踢一次，之后换 TA 就全瞎了 —— 2026-10-20 实测换完
# 新 TA 所有客户端都报系统错误，得手动删标记再踢一次才恢复。
#
# 幂等：同一个 TA 实例只踢一次。take_over 成功时调一次，hold 每轮也调一次。
kick_host() {
  host_pid=$(pidof com.tencent.soter.soterserver 2>/dev/null | awk '{print $1}')
  ta_pid=$(cat "$PIDFILE" 2>/dev/null)
  kicked_ta=$(cat "$TAKEOVER_PID" 2>/dev/null)
  if [ -n "$host_pid" ] && [ -n "$ta_pid" ] && [ "$kicked_ta" != "$ta_pid" ]; then
    log "restarting soter host pid=$host_pid so it rebinds our service (ta=$ta_pid)"
    kill -9 "$host_pid" 2>/dev/null
    echo "$ta_pid" > "$TAKEOVER_PID" 2>/dev/null
  fi
}

# 原厂 HAL 被谁拉回来了（init 重启、别的模块 ctl.start）就再抢一次：服务名被抢走时
# 检测器会看到 -20，比不接管还难查。
hold() {
  pid=$(daemon_pid)
  if [ -z "$pid" ]; then
    take_over && return 0
  fi
  if [ "$(hal_state)" = "running" ] || ! service_present; then
    log "stock HAL came back or our service vanished; re-taking over"
    take_over && return 0
  fi
  # 服务名和守护都正常，但 TA 实例可能已经换过了（被重新拉起）：那也得重踢。
  kick_host
}

release() {
  stop_daemon
  if [ "$(hal_state)" != "running" ]; then
    log "starting stock SOTER HAL"
    setprop ctl.start "$HAL" 2>/dev/null
  fi
}

case "$1" in
  status)
    if [ -n "$(daemon_pid)" ]; then
      echo "soterta=us hal=$(hal_state) service=$(service_present && echo yes || echo no)"
    else
      echo "soterta=none hal=$(hal_state) service=$(service_present && echo yes || echo no)"
    fi
    exit 0
    ;;
  enable)
    stop_daemon
    take_over
    exit $?
    ;;
  disable)
    release
    exit 0
    ;;
esac

# 默认：一次 converge（service.sh 的 keep-alive 循环会反复调这个）。
if enabled; then
  hold
else
  release
fi
