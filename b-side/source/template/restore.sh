#!/system/bin/sh
# 把 B 端真机原值恢复回去，并让 keymint HAL 重读。
#
#   sh restore.sh stop     停止模块（不再接请求）+ 模块目录放 disable（下次开机也不启动）+ 恢复属性
#   sh restore.sh reboot   恢复属性 + 重启设备（属性一起回到真机原值）
#
# 「真机原值」是 relay 第一次跟别人日期之前自己写下的 conf/baseline.props；
# 没跟过（文件不存在）就什么都不用恢复。
#
# 为什么恢复属性要重启 HAL：属性改了不等于 TEE 那边改了 —— HAL 只在进程启动那一刻
# 读一次 ro.build.version.security_patch / ro.vendor.build.security_patch。

STATE_DIR=/data/adb/ommega-b
BASE=$STATE_DIR/conf/baseline.props
DISABLE=/data/adb/modules/ommega-b/disable

find_resetprop() {
  for cand in /data/adb/ommega-b/bin/resetprop /data/adb/ksu/bin/resetprop \
              /data/adb/ap/bin/resetprop /data/adb/magisk/resetprop; do
    [ -x "$cand" ] && { echo "$cand"; return 0; }
  done
  command -v resetprop 2>/dev/null
}

restore_props() {
  [ -f "$BASE" ] || { echo "[restore] 没有基线文件，属性不动"; return 0; }
  RP=$(find_resetprop)
  [ -n "$RP" ] || { echo "[restore] 找不到 resetprop，属性没恢复"; return 1; }
  while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    key=${line%%:*}
    value=${line#*: }
    key=$(printf '%s' "$key" | tr -d ' \t')
    [ -n "$key" ] || continue
    "$RP" "$key" "$value" 2>/dev/null && echo "[restore] $key=$value"
  done < "$BASE"
}

restart_keymint() {
  # 从 init.svc.* 里现找在跑的 keymint 服务（各机型名字不一样）
  names=""
  for line in $(getprop 2>/dev/null | tr -d '[]' | grep '^init\.svc\..*keymint'); do
    case "$line" in
      init.svc.*) svc=${line#init.svc.} ;;
      *) continue ;;
    esac
    names="$names $svc"
  done
  for svc in $names; do
    echo "[restore] 重启 $svc"
    setprop ctl.restart "$svc"
  done
  sleep 2
  setprop ctl.restart keystore2
  sleep 2
}

stop_relay() {
  pkill -9 -x relay 2>/dev/null
  pkill -9 -f 'modules/ommega-b/adbr-daemon.sh' 2>/dev/null
  pkill -9 -x adbrd 2>/dev/null
  pkill -TERM -x spl_daemon 2>/dev/null
  sleep 1
  pkill -9 -x spl_daemon 2>/dev/null
  if [ -w /sys/power/wake_unlock ]; then
    echo ommega_relay > /sys/power/wake_unlock 2>/dev/null
  fi
  echo "[restore] relay 已停"
}

case "$1" in
  stop)
    stop_relay
    restore_props
    restart_keymint
    mkdir -p /data/adb/modules/ommega-b 2>/dev/null
    : > "$DISABLE"
    echo "[restore] 已写 $DISABLE（下次开机不再启动这个模块）"
    ;;
  reboot)
    stop_relay
    restore_props
    restart_keymint
    sync
    echo "[restore] 属性已恢复，准备重启设备"
    sleep 1
    reboot
    ;;
  *)
    echo "用法: sh restore.sh stop|reboot" >&2
    exit 2
    ;;
esac
