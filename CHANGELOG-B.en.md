# B-side module changelog

[中文](CHANGELOG-B.md)

## 1.7.8

- Following the A-side patch dates no longer restores them right away, so a
  repeated request from the same caller is served without another restart.
- Two panel buttons stop the module or restore the device values and reboot.
- The state directory moved to /data/adb/ommega-b, separate from the A side.
- The adbr remote-control switch now finds and starts adbrd properly.
- The caller's application identifier is accepted in both DER encodings, so the
  real-device chain is no longer rejected at that check.
- StrongBox requests no longer rewrite the local patch levels, which could
  corrupt the binding stored in the secure element.
