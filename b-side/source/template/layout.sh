#!/system/bin/sh
# B 端运行时目录：/data/adb/ommega-b/{bin,conf,run,db,logs}。
#
# 以前 B 跟 A 共用 /data/adb/ommega，两套模块的 bin/conf/run/logs 全挤在一个目录里，
# 光看目录分不出哪个文件是谁的。现在 B 独占 ommega-b。
#
# 这个脚本负责把老装机上的东西搬过来，幂等：新位置有东西就不动，没有才搬。
# 老位置有两种形态都要认：
#   1) 平铺：/data/adb/ommega/relay.conf、sessions.db …
#   2) 上一版的分目录：/data/adb/ommega/{bin/relay,conf/relay.conf,db/sessions.db…}
# 只搬 B 自己的东西 —— A 的 keymint/inject 那些一概不碰。

STATE_DIR=/data/adb/ommega-b
BIN_DIR=$STATE_DIR/bin
CONF_DIR=$STATE_DIR/conf
RUN_DIR=$STATE_DIR/run
DB_DIR=$STATE_DIR/db
LOG_DIR=$STATE_DIR/logs
OLD_DIR=/data/adb/ommega

migrate_from_shared() {
  mkdir -p "$BIN_DIR" "$CONF_DIR" "$RUN_DIR" "$DB_DIR" "$LOG_DIR" 2>/dev/null

  # 配置：这是唯一绝对不能丢的东西（里面有 server / device_id / token）
  if [ ! -f "$CONF_DIR/relay.conf" ]; then
    for src in "$OLD_DIR/conf/relay.conf" "$OLD_DIR/relay.conf"; do
      [ -f "$src" ] || continue
      mv -f "$src" "$CONF_DIR/relay.conf" 2>/dev/null
      break
    done
  fi

  # 会话库：一个别名一个 keyblob，几十 MB 到上百 MB，重刷要重新建料
  for f in sessions.db sessions.db-wal sessions.db-shm; do
    [ -f "$OLD_DIR/db/$f" ] && [ ! -e "$DB_DIR/$f" ] && mv -f "$OLD_DIR/db/$f" "$DB_DIR/$f" 2>/dev/null
    [ -f "$OLD_DIR/$f" ] && [ ! -e "$DB_DIR/$f" ] && mv -f "$OLD_DIR/$f" "$DB_DIR/$f" 2>/dev/null
  done
  for src in "$OLD_DIR/db/sessions" "$OLD_DIR/sessions"; do
    [ -d "$src" ] && [ ! -e "$DB_DIR/sessions" ] && mv -f "$src" "$DB_DIR/sessions" 2>/dev/null
  done

  # 运行期标记 / pid / 锁
  for f in relay.pid restart.all restart.keymint restart.injector spl_daemon.retry; do
    [ -f "$OLD_DIR/run/$f" ] && [ ! -e "$RUN_DIR/$f" ] && mv -f "$OLD_DIR/run/$f" "$RUN_DIR/$f" 2>/dev/null
    [ -f "$OLD_DIR/$f" ] && [ ! -e "$RUN_DIR/$f" ] && mv -f "$OLD_DIR/$f" "$RUN_DIR/$f" 2>/dev/null
  done
  for d in relay-service.lock adbr-daemon.lock; do
    [ -d "$OLD_DIR/run/$d" ] && [ ! -e "$RUN_DIR/$d" ] && mv -f "$OLD_DIR/run/$d" "$RUN_DIR/$d" 2>/dev/null
    [ -d "$OLD_DIR/$d" ] && [ ! -e "$RUN_DIR/$d" ] && mv -f "$OLD_DIR/$d" "$RUN_DIR/$d" 2>/dev/null
  done

  # 二进制：只**拷贝**不搬 —— 老目录里那份可能是 A 的（resetprop 两边都有一份）。
  # 模块自己 libs/ 里的才是出厂的，这里只是让热更新过的版本不丢。
  for f in relay adbrd spl_daemon resetprop; do
    [ -f "$OLD_DIR/bin/$f" ] && [ ! -e "$BIN_DIR/$f" ] && cp -f "$OLD_DIR/bin/$f" "$BIN_DIR/$f" 2>/dev/null
    [ -f "$OLD_DIR/$f" ] && [ ! -e "$BIN_DIR/$f" ] && cp -f "$OLD_DIR/$f" "$BIN_DIR/$f" 2>/dev/null
  done
  chmod 0755 "$BIN_DIR"/* 2>/dev/null

  # 日志：留个尾巴方便对照，A 的日志不碰
  for f in relay.log service.log adbr.log adbr-daemon.log self-reboot.log; do
    [ -f "$OLD_DIR/logs/$f" ] && [ ! -e "$LOG_DIR/$f" ] && mv -f "$OLD_DIR/logs/$f" "$LOG_DIR/$f" 2>/dev/null
    [ -f "$OLD_DIR/$f" ] && [ ! -e "$LOG_DIR/$f" ] && mv -f "$OLD_DIR/$f" "$LOG_DIR/$f" 2>/dev/null
  done
}

migrate_from_shared
