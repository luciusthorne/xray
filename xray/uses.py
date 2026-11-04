from pathlib import Path

from xray.elfscan import ElfScan, scan_elf
from xray.libresolve import find_library, ldconfig_cache
from xray.provenance import package_of

GROUPS = {
    "files": ["open", "openat", "creat", "close", "read", "write", "pread", "pwrite", "lseek", "fsync", "fdatasync", "ftruncate", "truncate", "unlink", "unlinkat", "rename", "renameat", "link", "symlink", "readlink", "readlinkat", "stat", "lstat", "fstat", "fstatat", "newfstatat", "statx", "chmod", "fchmod", "chown", "fchown", "lchown", "fchmodat", "fchownat", "utimensat", "futimens", "access", "faccessat", "fcntl", "dup", "dup2", "dup3", "pipe", "pipe2", "ioctl", "mmap", "munmap", "mkstemp", "mkdtemp", "realpath", "fopen", "fdopen", "fclose", "fread", "fgets", "fileno", "flock", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "posix_fadvise", "fallocate", "sendfile", "copy_file_range"],
    "directories": ["opendir", "fdopendir", "readdir", "closedir", "rewinddir", "mkdir", "mkdirat", "rmdir", "chdir", "fchdir", "getcwd", "fts_open", "fts_read", "fts_close", "fts_set", "scandir", "glob", "globfree"],
    "memory": ["malloc", "calloc", "realloc", "reallocarray", "free", "memcpy", "memmove", "mempcpy", "memset", "memcmp", "memchr", "memrchr", "posix_memalign", "aligned_alloc", "mprotect", "madvise", "mremap", "brk", "sbrk", "alloca", "obstack_free", "_obstack_begin", "_obstack_newchunk"],
    "strings": ["strlen", "strnlen", "strcmp", "strncmp", "strcasecmp", "strncasecmp", "strcoll", "strcpy", "strncpy", "stpcpy", "strcat", "strncat", "strchr", "strrchr", "strstr", "strchrnul", "strdup", "strndup", "strtol", "strtoul", "strtoll", "strtoull", "strtoimax", "strtoumax", "strtod", "atoi", "atol", "strtok", "strtok_r", "strspn", "strcspn", "strpbrk", "strerror", "strerror_r", "strsignal", "strxfrm", "qsort", "bsearch", "mbrtowc", "mbstowcs", "wcwidth", "mbsinit", "mbrlen", "wcrtomb", "iswprint", "towlower", "towupper", "tolower", "toupper", "isalpha", "isdigit", "isspace", "isprint", "iswalnum", "iswcntrl", "iswspace", "btowc", "wctob"],
    "stdio": ["printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "vsprintf", "vsnprintf", "dprintf", "vdprintf", "asprintf", "vasprintf", "puts", "fputs", "putc", "fputc", "putchar", "fwrite", "fflush", "getc", "fgetc", "getchar", "ungetc", "scanf", "sscanf", "fscanf", "getline", "getdelim", "setvbuf", "perror", "error", "error_at_line", "__fpending", "ferror", "feof", "clearerr", "fseek", "ftell", "rewind", "__overflow", "__uflow", "putc_unlocked", "fputc_unlocked", "fwrite_unlocked"],
    "time": ["time", "clock_gettime", "clock_getres", "gettimeofday", "localtime", "localtime_r", "gmtime", "gmtime_r", "mktime", "timegm", "strftime", "strptime", "nanosleep", "sleep", "usleep", "clock", "difftime", "tzset", "timer_create", "timer_settime", "timerfd_create"],
    "locale": ["setlocale", "localeconv", "nl_langinfo", "textdomain", "bindtextdomain", "gettext", "dcgettext", "dgettext", "dcngettext", "ngettext", "bind_textdomain_codeset", "iconv", "iconv_open", "iconv_close", "newlocale", "uselocale", "freelocale", "__ctype_b_loc", "__ctype_tolower_loc", "__ctype_toupper_loc", "__ctype_get_mb_cur_max"],
    "signals": ["signal", "sigaction", "sigprocmask", "sigemptyset", "sigfillset", "sigaddset", "sigdelset", "sigismember", "sigsuspend", "sigpending", "raise", "kill", "killpg", "alarm", "pause", "sigaltstack", "sigwait"],
    "processes": ["fork", "vfork", "execve", "execv", "execvp", "execl", "execlp", "execle", "posix_spawn", "posix_spawnp", "wait", "waitpid", "wait4", "system", "popen", "pclose", "getpid", "getppid", "setsid", "setpgid", "getpgid", "getuid", "geteuid", "getgid", "getegid", "setuid", "setgid", "getgroups", "setgroups", "getpwnam", "getpwuid", "getgrnam", "getgrgid", "getlogin", "prctl", "sched_yield", "sched_getaffinity", "getrlimit", "setrlimit", "getpriority", "setpriority", "umask", "isatty", "ttyname", "tcgetattr", "tcsetattr", "tcgetpgrp", "getrandom", "getentropy"],
    "environment": ["getenv", "setenv", "unsetenv", "putenv", "clearenv", "secure_getenv", "environ", "__progname", "program_invocation_name", "program_invocation_short_name", "getopt", "getopt_long", "getopt_long_only", "optarg", "optind", "opterr", "optopt", "gethostname", "sysconf", "pathconf", "confstr", "uname"],
    "network": ["socket", "connect", "bind", "listen", "accept", "accept4", "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg", "getsockopt", "setsockopt", "getsockname", "getpeername", "shutdown", "socketpair", "poll", "ppoll", "select", "pselect", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "getaddrinfo", "freeaddrinfo", "gai_strerror", "gethostbyname", "getservbyname", "getnameinfo", "inet_ntop", "inet_pton", "inet_addr", "htons", "ntohs", "htonl", "ntohl", "if_nametoindex"],
    "threads": ["pthread_create", "pthread_join", "pthread_self", "pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_init", "pthread_mutex_destroy", "pthread_cond_wait", "pthread_cond_signal", "pthread_cond_broadcast", "pthread_once", "pthread_key_create", "pthread_getspecific", "pthread_setspecific", "pthread_attr_init", "pthread_detach", "sem_init", "sem_wait", "sem_post", "thrd_create", "call_once"],
    "security": ["getfilecon", "lgetfilecon", "fgetfilecon", "setfilecon", "lsetfilecon", "fsetfilecon", "freecon", "getcon", "setcon", "matchpathcon", "is_selinux_enabled", "is_selinux_mls_enabled", "selabel_open", "selabel_lookup", "selabel_close", "security_check_context", "getprevcon", "setexeccon", "setfscreatecon"],
    "runtime": ["__libc_start_main", "__cxa_atexit", "__cxa_finalize", "__gmon_start__", "__stack_chk_fail", "__assert_fail", "abort", "exit", "_exit", "atexit", "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable", "__errno_location", "_Unwind_Resume", "__gxx_personality_v0", "dlopen", "dlsym", "dlclose", "dlerror", "dl_iterate_phdr", "__tls_get_addr", "__register_atfork", "__libc_single_threaded"],
}

for _group, _names in {
    "strings": ["isalnum", "isblank", "iscntrl", "isgraph", "islower", "ispunct", "isupper", "isxdigit", "regcomp", "regexec", "regfree", "re_search", "re_compile_pattern", "re_set_syntax", "strverscmp", "rawmemchr", "mbrtoc32"],
    "stdio": ["stdout", "stderr", "stdin", "__fwriting"],
    "directories": ["dirfd", "fnmatch"],
    "files": ["utimes", "futimesat", "mkostemp"],
    "security": ["getfscreatecon"],
    "locale": ["nl_langinfo_l"],
    "environment": ["__progname_full"],
    "runtime": ["_setjmp", "setjmp", "longjmp"],
}.items():
    GROUPS.setdefault(_group, []).extend(_names)

PREFIXES = (
    ("curl_", "network"),
    ("nghttp2_", "network"),
    ("libssh2_", "network"),
    ("acl_", "security"),
    ("SSL_", "security"),
    ("EVP_", "security"),
    ("OPENSSL_", "security"),
    ("ERR_", "security"),
    ("BZ2_", "compression"),
    ("deflate", "compression"),
    ("inflate", "compression"),
    ("lzma_", "compression"),
    ("ZSTD_", "compression"),
    ("xml", "parsing"),
    ("re_", "strings"),
    ("selinux_", "security"),
    ("is_selinux", "security"),
    ("security_", "security"),
    ("selabel_", "security"),
    ("cap_", "security"),
    ("Py", "python"),
    ("_Py", "python"),
    ("pthread_", "threads"),
    ("sem_", "threads"),
)

_LOOKUP = {name: group for group, names in GROUPS.items() for name in names}


def _candidates(name):
    yield name

    base = name

    for prefix in ("__isoc23_", "__isoc99_", "__"):
        if base.startswith(prefix):
            base = base[len(prefix):]
            yield base
            break

    for suffix in ("_chk", "_unlocked", "64"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            yield base


def classify(name):
    """Return the group a libc or library name belongs to, or "other"."""

    for candidate in _candidates(name):
        if candidate in _LOOKUP:
            return _LOOKUP[candidate]

    for prefix, group in PREFIXES:
        if name.startswith(prefix):
            return group

    return "other"


def group_imports(names):
    """Return {group: sorted names}, with unknown names under "other"."""

    found = {}

    for name in names:
        found.setdefault(classify(name), []).append(name)

    return {group: tuple(sorted(items)) for group, items in found.items()}


def _ordered(groups):
    known = [g for g in groups if g != "other"]
    known.sort(key=lambda g: (-len(groups[g]), g))

    return known + (["other"] if "other" in groups else [])


def uses_summary(names):
    """Return a one-line "Uses: files (14), ..." summary, or None.

    None when no name is recognized, so unknown-only lists add no line.
    """

    groups = group_imports(names)

    if not [g for g in groups if g != "other"]:
        return None

    parts = [f"{g} ({len(groups[g])})" for g in _ordered(groups)]

    return "Uses: " + ", ".join(parts)


def attribute_imports(names, exports):
    """Return {library: sorted names} for names a library exports.

    exports maps a library name to the set of names it defines. The
    first library that exports a name gets it.
    """

    found = {}

    for name in names:
        for library, defined in exports.items():
            if name in defined:
                found.setdefault(library, []).append(name)
                break

    return {library: tuple(sorted(items)) for library, items in found.items()}


def uses_lines(path, max_names=40):
    """Return report lines listing an ELF binary's imports.

    Names the purpose table knows (libc and friends) are grouped by
    purpose. The rest are attributed to the needed library that exports
    them, and only names no needed library exports stay in other. A name
    means the binary can call it, not that it does at run time.
    """

    scan = scan_elf(path)

    if scan == ElfScan():
        return ["No ELF information found (is readelf installed?)"]

    groups = group_imports(scan.imports)
    unknown = groups.pop("other", ())
    exports = {}
    cache = {}

    if unknown and scan.needed:
        cache = ldconfig_cache()

        for library in scan.needed:
            found = find_library(library, cache)

            if found is not None:
                exports[library] = set(scan_elf(Path(found)).exports)

    by_library = attribute_imports(unknown, exports)
    claimed = {name for names in by_library.values() for name in names}
    leftover = tuple(sorted(set(unknown) - claimed))
    lines = []

    def block(title, names):
        lines.append(f"{title} ({len(names)}):")
        lines.extend(f"- {name}" for name in names[:max_names])

        if len(names) > max_names:
            lines.append(f"- ... and {len(names) - max_names} more")

    for group in _ordered(groups):
        block(group, groups[group])

    for library in sorted(by_library, key=lambda l: (-len(by_library[l]), l)):
        owner = find_library(library, cache)
        package = package_of(owner) if owner else None
        label = f"From {library} ({package})" if package else f"From {library}"
        block(label, by_library[library])

    if leftover:
        block("other", leftover)

    lines.append(
        "A name here means the binary can call it, not that it does at "
        "run time (see --trace)."
    )

    return lines
