# Termux package

`build.sh` is a [termux-packages](https://github.com/termux/termux-packages) recipe
for `xray-trust` (the command is `xray`), in the same form as Termux's other
pure-Python packages: the release sdist, installed by Termux's Python build
step. To submit it, copy it to `packages/xray-trust/build.sh` in a fork of
termux-packages, set `TERMUX_PKG_SHA256` to the release sdist's SHA-256, and
open a pull request there.

Until it is in Termux's repository, install it in Termux with pip:

```sh
pkg install python binutils file
pip install xray-trust
```

`binutils` gives GNU's tools as `greadelf`, `gobjdump`, ...; XRAY uses them when
the plain names (from `llvm`) are not installed, and prefers GNU `objdump`
either way, because it reads GNU's disassembly.
