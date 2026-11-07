# Cross-distribution study: same release, different builds

**Question:** Arch and Debian often build the same upstream release from the
same source. If their builds differ in what they are *able to do*, something
entered at build time. That was the shape of the 2024 xz backdoor, which was
only injected into Debian and RPM builds. Is "the two builds differ" a usable
signal, or is it buried in ordinary build differences?

**Method** (`tools/crossdistro_study.py`, raw results in
`docs/data/crossdistro-study-2026-11-06.jsonl`):

- the 500 most popular Arch packages (pkgstats), at the versions in the Arch
  capability log;
- the Debian source package found through Repology, and Debian's build of the
  *same upstream version* from snapshot.debian.org (amd64 and `all` binary
  packages; no debug symbols, documentation or headers);
- `xray compare` on every file present in both builds, paired by file name.

## Results

| | Packages |
| --- | --- |
| In the top 500 | 499 |
| No ELF files | 64 |
| No Debian build of the same upstream version | 184 |
| **Compared** (3,888 files present in both builds) | **241** |
| Differ in any capability | 108 (45%) |
| Differ in a **strong** capability | 29 (12%) |

Strong differences, by kind (a package can have several):

| Kind | Packages | What explains them |
| --- | --- | --- |
| A call class (exec, net, dlopen, identity, shell, kernel, ptrace) | 25 | distribution patches and configure options, for example Debian's openssh `scp`/`sftp`, Debian's `libaudit` importing `execve`, Arch's e2fsprogs tools using `dlopen` |
| **Dependence on the dynamic loader** | **4**: gdb, libplacebo, librsvg, util-linux | in all four, only Debian's build links `ld-linux` and imports only `__tls_get_addr` (thread-local storage), with no IFUNC resolvers |
| **Loader hook** (dependence on the loader *and* IFUNC resolvers) | **0** | — |

Weak differences (libraries, search paths) are common and are not counted
above. An earlier draft also counted constructors as strong; they differed in
18 packages because of build flags, so `xray compare` now treats them as weak.

## The xz backdoor against this background

Debian's backdoored liblzma5 5.6.1-1 compared with Arch's xz 5.6.1-1, the
same release built without the payload (see `docs/real-xz.md`):

```
[STRONG] liblzma.so.5.6.1
    only the second build: links the dynamic loader and has IFUNC resolvers ...
    only the second build: new library: ld-linux-x86-64.so.2
```

- The **generic** cross-build check (dependence on the dynamic loader differs)
  flags the backdoored xz alongside 4 of the 241 other packages: a shortlist
  of about 2% that one person can review in minutes. The other four are
  explained by thread-local storage.
- Adding "and the library has IFUNC resolvers" (the loader-hook rule) leaves
  the backdoored xz alone: no package in the study matches.

## Honest reading

- **Any strong difference is not an alarm.** 12% of packages differ strongly
  between distributions for ordinary reasons. Those differences are leads that
  a distribution patch or configure flag usually explains.
- **Dependence on the dynamic loader is a narrow signal.** It shortlisted the
  real backdoor among ~2% of packages with no rule written for it. That is the
  strongest claim this study supports.
- **The loader-hook refinement was written after seeing the backdoor**
  (`docs/real-xz.md`). It finds nothing else here, but it describes one
  technique.
- **Disagreement, not majority.** For xz 5.6.1 two of three distributions
  (Debian and Fedora) carried the payload, which targeted .deb and .rpm
  builds. A majority vote would have blamed Arch's clean build; any
  difference between builds is the lead (docs/real-xz.md).
- **Coverage:** 184 packages had no Debian build of the same upstream version,
  and only files present in both builds are compared. The Fedora run below
  adds a third opinion.

## Second opinion: Arch against Fedora (2026-11-07)

Same method with `--against fedora`: the newest `fcNN` build of the same
upstream version from Fedora's build system (kojipkgs.fedoraproject.org),
x86_64 and noarch RPMs without debug, devel, doc or test subpackages. Raw
results in `docs/data/crossdistro-fedora-2026-11-07.jsonl`.

| | Packages |
| --- | --- |
| In the top 500 | 499 |
| No ELF files | 64 |
| No Fedora build of the same upstream version | 183 |
| **Compared** (3,600 files present in both builds) | **244** |
| Differ in any capability | 108 (44%) |
| Differ in a **strong** capability | 40 (16%) |

| Kind | Packages | What explains them |
| --- | --- | --- |
| A call class | 14 | packaging and options: e2fsprogs tools built with `dlopen` on Arch; Lua on Arch built with `dlopen`/`popen`; tpm2-tss TCTI modules; and **systemd**, where Fedora's `systemd-standalone-*` packages build the shared code into `systemd-repart` and `systemd-sysusers`, so calls that live in `libsystemd-shared` on Arch appear in the binary itself (a pairing artifact, not a new capability) |
| **Dependence on the dynamic loader** | **31**, always Arch's build | thread-local storage: every one imports only `__tls_get_addr`. Fedora compiles x86-64 with TLS descriptors (`R_X86_64_TLSDESC`), which need no symbol from `ld-linux`; Arch uses the traditional model (`R_X86_64_DTPMOD64` + `__tls_get_addr`). Checked by hand on libsodium 1.0.22: Fedora 1 TLSDESC relocation, no `ld-linux` in `DT_NEEDED`; Arch 1 DTPMOD64 relocation, links `ld-linux` |
| **Loader hook** (loader *and* IFUNC resolvers) | **0** | — none of the 31 libraries has IFUNC resolvers |

### What the third opinion changes

- **The generic loader check depends on which pair you compare.** Against
  Debian it shortlisted ~2% of packages; against Fedora 13%, all explained by
  one compiler setting (the TLS dialect). It cannot simply ignore
  `__tls_get_addr`: the real backdoored liblzma links `ld-linux` for exactly
  that symbol (`docs/real-xz.md`). So the narrow, portable signal is the
  **loader hook**, which stays at zero false positives across both pairs and
  ~485 compared packages, while flagging the backdoored builds of Debian and
  Fedora.
- **Strong call-class differences stay rare and explainable** (25 packages
  against Debian, 14 against Fedora), mostly patches, configure options, or
  how a distribution splits a program into packages.
- **Pairing by file name has limits.** When one distribution ships a
  differently linked variant under the same name (Fedora's standalone
  systemd tools), capabilities move between the binary and its libraries.
  A difference report is a lead; the evidence (`xray compare`, `xray why`)
  says where each call lives.
