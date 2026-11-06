# XRAY against the real xz backdoor (CVE-2024-3094)

The toy demo in `demo/xz-style` shows the pattern. This is the real thing:
the backdoored `liblzma5` packages Debian unstable shipped in March 2024,
compared with the clean releases around them and with Arch Linux's builds of
the same versions. Run it yourself with `demo/real-xz/run.sh`.

XRAY never loaded or ran the backdoored library: it only read it with
`readelf`.

## The packages

| Package | Source | SHA-256 | Payload |
| --- | --- | --- | --- |
| liblzma5 5.4.5-0.3 | snapshot.debian.org | `ed3fe5e4…07c92` | no |
| liblzma5 5.6.0-0.2 | snapshot.debian.org | `2ed51ae8…d3d98` | **yes** |
| liblzma5 5.6.1-1 | snapshot.debian.org | `15b08cba…cb7` | **yes** |
| liblzma5 5.6.1+really5.4.5-1 (the revert) | snapshot.debian.org | `6fb58443…3592` | no |
| liblzma5 5.6.2-1, 5.6.4-1 | snapshot.debian.org | — | no |
| xz 5.4.6-1, 5.6.0-1, 5.6.1-1, 5.6.1-2, 5.6.1-3 | archive.archlinux.org, signatures checked | — | no |

The malicious build step only ran in Debian and RPM builds, so Arch's 5.6.0
and 5.6.1-1, built from the same release tarballs, contain the release's new
code but not the payload. That makes them the control.

## Fedora Rawhide, a second independent test

Fedora's build system (Koji) still serves Rawhide's xz builds from March 2024.
None of them were used while designing the rule:

| Fedora xz-libs | links the loader | IFUNC resolvers | XRAY loader hook |
| --- | --- | --- | --- |
| 5.4.6-3.fc41 | no | 0 | not flagged |
| **5.6.0-2.fc41** | **yes** | 2 | **flagged** |
| 5.6.0-3.fc41 | no | 0 | not flagged |
| **5.6.1-1.fc41** | **yes** | 2 | **flagged** |

5.6.0-3 is the rebuild that disabled IFUNC after Valgrind errors, the errors
that helped expose the backdoor. With IFUNC off the hook was not there, and
XRAY does not flag it. `xray drift` shows the hook arriving in 5.6.0-2,
leaving in 5.6.0-3 and returning in 5.6.1-1, and `xray compare` of Arch's
clean 5.6.1-1 with Fedora's 5.6.1-1 is a strong difference.

**Two of three distributions carried the payload** (Debian and Fedora; the
attacker targeted .deb and .rpm builds). Comparing builds across
distributions therefore works as "any disagreement is a lead", not as a
majority vote: a vote would have called Arch's clean build the odd one out.

## What the files show

| liblzma build | DT_NEEDED | new import | IFUNC resolvers |
| --- | --- | --- | --- |
| Debian 5.4.5 | libc | — | 0 |
| **Debian 5.6.0 (backdoored)** | libc, **ld-linux-x86-64.so.2** | **`__tls_get_addr`** | 2 |
| **Debian 5.6.1 (backdoored)** | libc, **ld-linux-x86-64.so.2** | **`__tls_get_addr`** | 2 |
| Debian 5.6.1+really5.4.5 | libc | — | 0 |
| Debian 5.6.2, 5.6.4 | libc | — | 0 |
| Arch 5.4.6 | libc | — | 0 |
| Arch 5.6.0, 5.6.1-1/2/3 | libc | — | 2 |

- The two IFUNC resolvers (CRC32 and CRC64) came with the 5.6 releases'
  source. They are in every 5.6.0/5.6.1 build, with or without the payload,
  so they do not distinguish the backdoor. The payload hid inside them.
- Linking the dynamic loader itself appears only in the backdoored builds.

## What XRAY reports

`xray drift` from clean 5.4.5 to backdoored 5.6.0 or 5.6.1:

```
Capabilities gained (3)
  liblzma.so.5.6.1: links the dynamic loader and has IFUNC resolvers: code that runs inside
                    the loader before main, the hook of the 2024 xz backdoor
  liblzma.so.5.6.1: new library: ld-linux-x86-64.so.2
  liblzma.so.5.6.1: IFUNC resolvers: 0 -> 2
```

Arch 5.4.6 to 5.6.1-1 (no payload): one gain, `IFUNC resolvers: 0 -> 2`.
Backdoored 5.6.1 to the revert: `dropped library: ld-linux-x86-64.so.2`.

`xray inspect` on the backdoored `.so`, and `xray scan` on a machine that had
it installed, list it under "Worth a look". On the Arch build of the same
version, nothing is flagged.

## The loader-hook rule, and how often it fires

The rule: **a library outside the loader's own family (ld.so, libc, libm,
libmvec) that links the dynamic loader and has IFUNC resolvers.** Its
resolvers run inside the loader while it relocates the program, before `main`
and before any constructor.

Neither half is rare alone: 152 of the 2,692 libraries on the development
machine link the loader (thread-local storage needs it), and IFUNCs are
common in optimized code. Together:

| Corpus | Libraries that match |
| --- | --- |
| Debian liblzma5, 7 builds | the 2 backdoored ones |
| Arch xz, 5 builds | 0 |
| Fedora xz-libs, 4 builds | the 2 backdoored ones |
| 1,019 archives of the 500 most popular Arch packages (`tools/arch_capability_log.py`) | only glibc's libc, libm and libmvec, which the rule excludes |
| Every library on a full Arch desktop (`/usr/lib`) | only glibc |
| `xray scan` of the same machine: 4,130 programs, 5,662 files | 0 findings |

## What this does and does not show

- **The rule was written after looking at the backdoor.** It shows that XRAY
  now detects this pattern with no false positives on the corpora above. It
  does not show that XRAY would have caught the backdoor in March 2024.
- **What XRAY would have said in March 2024** without the rule: `drift`
  reported "new library: ld-linux-x86-64.so.2" and "IFUNC resolvers: 0 -> 2"
  for liblzma as gains. Those are generic gains a reviewer would have had to
  notice among others. A contract made on 5.4.5 pinned `ifuncs=0` and would
  have broken on upgrade, but so would the clean Arch build.
- **A next backdoor can avoid this rule**, for example by not needing
  `__tls_get_addr`, or by hooking through a constructor instead. The rule
  catches one technique. Contracts and enforcement limit what any payload can
  do once it runs, whatever the technique.
- The payload's behaviour (hooking `RSA_public_decrypt` in sshd) is not
  visible in a library's imports, so no import-based profile sees it directly.
