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
  and only files present in both builds are compared. Fedora builds would add a
  third opinion; that is planned.
