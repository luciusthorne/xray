# XRAY capability contract, version 1

A capability contract says what one program may do: which programs it may
execute, which files it may load, read and write, and which network access it
may use. It is a plain text file meant to be read in review, kept in version
control next to the program, and shipped by packagers. Any tool may read or
write it; XRAY generates, checks, enforces and minimizes contracts
(`xray contract generate|check|enforce|minimize`).

## Example

```
# XRAY capability contract (docs/contract-spec.md)
xray-contract 1
program /usr/bin/xdg-mime
sha256 a587107ff995a5f907ab1b731316a169348c6b0383caf8fd151ff21f89615f3f
generated 2026-11-06 from static evidence and a traced run
workload xdg-mime query default text/plain

[exec]
/usr/bin/xdg-mime  # observed; the program itself
/usr/bin/bash caps=dynload,exec,identity,net ifuncs=0 ctors=1  # required: declared: #!/bin/sh (/bin/sh is a link to /usr/bin/bash) (xdg-mime:1)
/usr/bin/grep      # required: observed; inferred: runs `grep` (xdg-mime:322)

[load]
/usr/lib/ld-linux-x86-64.so.2  # declared: PT_INTERP /lib64/ld-linux-x86-64.so.2 (bash)
/usr/lib/libc.so.6             # observed; declared: DT_NEEDED libc.so.6 (bash)

[read]
~/.config/mimeapps.list  # required: observed
/usr/share/applications  # required: observed

[write]

[net]
none
```

## Syntax

- The file is UTF-8 text. `#` starts a comment that runs to the end of the
  line. Blank lines are ignored.
- The first non-comment line is `xray-contract 1`.
- Header lines follow, each `key value`:
  - `program` (required): the absolute path of the program the contract is for.
  - `sha256`: the SHA-256 of the program file when the contract was written.
  - `package`: the package that owned it, as `name version`.
  - `generated`: free text: when and from what evidence.
  - `workload`: the command line the observations and minimization used.
- Sections follow, each opened by a line `[name]`: `exec`, `load`, `read`,
  `write`, `net`. A section may be empty or missing. Unknown sections and
  unknown header keys are errors, so a reader never silently ignores a grant.

### Path entries (`exec`, `load`, `read`, `write`)

One entry per line:

- an absolute path: exactly that file, or that directory and everything
  beneath it;
- `~/...`: the same, relative to the home directory of the user who runs the
  program;
- a final component with `*`, `?` or `[...]` (shell glob rules): the matching
  names in that directory, not below it;
- a final `/**`: everything beneath that directory, at any depth.

`**` anywhere else is an error. Paths name files after symbolic links are
resolved, and may not contain spaces.

### Capability pins (`exec` and `load`)

An `[exec]` or `[load]` entry may be followed by `KEY=VALUE` attributes that
pin what that file is *able to do*, read from its contents:

- `caps=CLASS,...` (or `caps=-` for none): the classes of calls the file
  imports: `net`, `exec`, `shell`, `dynload`, `identity`, `ptrace`, `kernel`;
- `ifuncs=N`: at most N IFUNC resolvers (code the loader runs to pick an
  implementation);
- `ctors=N`: at most N constructors (code that runs before `main`).

```
/usr/lib/liblzma.so.5.8.4 caps=- ifuncs=0 ctors=2  # declared: DT_NEEDED liblzma.so.5
```

A file that gains a class or exceeds a count breaks the contract even when its
name and API stay the same: the case of the 2024 xz backdoor. Updates that add
no capability pass. Unknown attributes are errors.

### Meaning

| Section | Grants |
| --- | --- |
| `exec` | executing the file (and reading it) |
| `load` | loading the file as code into the process: shared libraries, the ELF interpreter, modules a script imports or sources (reading it) |
| `read` | opening for reading, listing directories |
| `write` | creating, changing, truncating, renaming and removing (and reading) |
| `net` | see below |

### `[net]` entries

- `none`: no network at all (also the meaning of an empty section);
- `any`: no network limits;
- `unix`: unix domain sockets, including abstract ones;
- `connect tcp PORT`, `connect udp PORT`, `bind tcp PORT`, `bind udp PORT`,
  with `*` for any port.

### Comments as evidence

Generated contracts put the evidence for each entry in its comment, starting
with the basis: `observed` (seen in a traced run), `declared` (stated by
metadata the system acts on, such as `DT_NEEDED` or a shebang), `inferred`
(read from code and resolved as this machine would), `guessed`, and, after
minimization, `required` (removing the entry changed the workload's result).
Comments carry no meaning for enforcement.

## Baseline

Every contract allows, without listing them, reading `/etc/ld.so.cache`,
`/etc/ld.so.preload`, `/etc/localtime`, locale, gconv and zoneinfo data under
`/usr/lib`, `/usr/lib64` and `/usr/share`, and everything under `/proc` and
`/sys`, plus reading and writing `/dev/null`, `/dev/zero`, `/dev/full`,
`/dev/random`, `/dev/urandom`, `/dev/tty` and `/dev/pts/*`.

## Enforcement by XRAY

`xray contract enforce` runs the program under Linux Landlock, unprivileged:
`exec`, `load`, `read` and `write` become Landlock file system rights, and
`connect tcp`/`bind tcp` ports become Landlock network rules (kernel ABI 4+).
Abstract unix sockets are denied unless `[net]` allows `unix` (ABI 6+). When
`[net]` is empty or `none`, the program also runs in a private network
namespace (bubblewrap), which removes UDP and every other protocol as well.

Known differences between the contract and its enforcement:

- Landlock grants rights per file or per directory tree. A `[read]`,
  `[exec]` or `[load]` entry such as `dir/*.conf` is enforced as the files that
  match when the program starts (files created later are not readable); a
  `[write]` glob, and writing a file that does not exist yet, are enforced as
  write access to the directory.
- UDP ports are not limited by Landlock: a contract with any network entry
  allows UDP.
- Connecting to a unix socket file is not limited by Landlock on every kernel.

`xray contract check --trace` checks an observed run at the exact granularity
of the contract.

## Minimal contracts

`xray contract minimize CONTRACT -- ARGS` runs the workload under the contract,
then removes entries (delta debugging) while the exit status, stdout and stderr
stay the same. Every remaining entry is marked `required`. A minimal contract
is minimal for that workload only; other inputs may need more. Libraries the
dynamic loader must map for the remaining programs are kept without trying.

## Versioning

A reader must reject a contract whose first line is not a version it
supports. Version 1 readers reject unknown sections and header keys. New
sections or keys mean a new version.
