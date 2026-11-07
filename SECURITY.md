# Security policy

XRAY reads programs and, in a few places, acts on them: it runs the pacman
hook as root, enforces contracts with Landlock and bubblewrap, and downloads
debug files and source code. Reports about those parts are especially welcome.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability**
on this repository. Do not open a public issue for a security problem.

Include what you ran, what happened and what you expected; a proof of concept
helps. You will get an answer within a week, and a fix or a plan with a date
for anything confirmed. Reporters are credited in the release notes unless
they ask not to be.

## Supported versions

Only the latest release gets security fixes.

## In scope

- **The pacman hook** (`xray hook`): it runs as root during upgrades; anything
  that lets a package, a user-writable file or the environment influence it.
- **Contract enforcement** (`xray contract enforce`, `contract systemd`): a
  program escaping the Landlock or bubblewrap rules a contract asks for, or a
  contract that grants more than it says.
- **Downloads**: debuginfod debug files and sources, crates.io archives,
  rust-src, the Go module proxy and Go repository, and upstream archives from
  Arch's `.SRCINFO` (checksum checked). Path traversal on extraction, checksum
  bypass, or fetching from a place other than the one shown.
- **`xray --serve`**: it binds to 127.0.0.1 and serves only files of the graph
  it shows; reading other files, or reaching it from another origin.
- **Signatures and logs** (`xray attest`, `xray log verify`): accepting
  something forged or altered.
- Running code by mistake: XRAY reads files and never executes the programs it
  analyses, except under `--trace`, `contract enforce`, `minimize` and
  `build --check`, which run the command you give them.

## Not vulnerabilities

- XRAY reporting fewer links than a program really has. Static reading has
  blind spots by design, and every report lists them; better coverage is still
  welcome as an ordinary issue.
- A program XRAY did not flag turning out to be malicious. XRAY never claims a
  program is safe.
- By-name source matches (labelled "a guess") that point at the wrong code.
