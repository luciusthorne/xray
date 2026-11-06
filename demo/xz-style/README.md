# Demo: catching an xz-style library backdoor

In 2024 a backdoor reached xz/liblzma 5.6.0 and 5.6.1. The library's
public behaviour did not change; what changed was what the library was
*able to do*: an IFUNC resolver and code that ran before `main` in every
program that loaded it, including sshd.

`run.sh` re-enacts that pattern safely with a toy library, `lzdemo`:

| | 5.6.0 (`lzdemo-clean.c`) | 5.6.1 (`lzdemo-backdoored.c`) |
| --- | --- | --- |
| API | `lz_compress` | `lz_compress`, unchanged |
| IFUNC resolvers | 0 | 1 |
| constructors | 1 | 2 |
| imports | — | `system` |

The payload is harmless: it writes a marker file named by
`XRAY_DEMO_MARK` inside `work/`.

```sh
demo/xz-style/run.sh          # needs gcc, bsdtar, strace and Landlock
```

What XRAY shows, step by step:

1. `xray contract generate --trace` + `minimize` writes the app's contract from
   the clean release. `[load]` entries pin what each library is able to do:
   `caps=- ifuncs=0 ctors=1`.
2. `xray drift old.pkg.tar.zst new.pkg.tar.zst` compares the two releases
   before installing: **now uses shell: system; IFUNC resolvers 0 → 1;
   constructors 1 → 2**.
3. `xray log add` records both releases in a hash-chained capability log;
   `xray log history lzdemo` shows the same gains, `xray log verify` proves the
   history was not rewritten.
4. After the upgrade, `xray contract check` fails without running anything:
   the library entry allowed `caps=-`, and the file now uses `system`.
5. `xray contract check --trace` runs the app and reports what the payload
   did: it executed `/usr/bin/bash` and wrote the marker.
6. `xray contract enforce` runs the app under its contract: the payload's
   exec is denied by Landlock and the app still prints its result.
7. Without the contract, the payload runs.

What this does not claim: a backdoor that adds no import, IFUNC or
constructor, and stays inside what the contract already allows, is not
visible to these checks. Enforcement still limits what it can do.
