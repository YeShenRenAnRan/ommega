# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.8

- The spoofed values only keep the boot hash and the boot patch level.
- Declaring no device ID attestation is off by default; taking over SOTER is on.
- Global scope is on by default: ordinary apps go through the module while system
  services and ROM components keep their original backend.
- Engineer mode key operations work out of the box.
- Saving the configuration from the panel no longer fails with "No such file or directory":
  a missing state symlink or bundled resetprop is now recreated automatically.
- The SOTER log no longer repeats the same resolution line every few seconds.
