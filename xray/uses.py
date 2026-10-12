from xray.elfscan import ElfScan, scan_elf

GROUPS = {
    "files": (
        "open openat creat close read write pread pwrite lseek fsync fdatasync "
        "ftruncate truncate unlink unlinkat rename renameat link symlink "
        "readlink readlinkat stat lstat fstat fstatat newfstatat statx "
        "chmod fchmod chown fchown lchown fchmodat fchownat utimensat futimens "
        "access faccessat fcntl dup dup2 dup3 pipe pipe2 ioctl mmap munmap "
        "mkstemp mkdtemp realpath fopen fdopen fclose fread fgets fileno "
        "flock getxattr lgetxattr fgetxattr listxattr llistxattr "
        "posix_fadvise fallocate sendfile copy_file_range"
    ).split(),
    "directories": (
        "opendir fdopendir readdir closedir rewinddir mkdir mkdirat rmdir "
        "chdir fchdir getcwd fts_open fts_read fts_close fts_set scandir "
        "glob globfree"
    ).split(),
    "memory": (
        "malloc calloc realloc reallocarray free memcpy memmove mempcpy memset "
        "memcmp memchr memrchr posix_memalign aligned_alloc mprotect madvise "
        "mremap brk sbrk alloca obstack_free _obstack_begin _obstack_newchunk"
    ).split(),
    "strings": (
        "strlen strnlen strcmp strncmp strcasecmp strncasecmp strcoll strcpy "
        "strncpy stpcpy strcat strncat strchr strrchr strstr strchrnul strdup "
        "strndup strtol strtoul strtoll strtoull strtoimax strtoumax strtod "
        "atoi atol strtok strtok_r strspn strcspn strpbrk strerror strerror_r "
        "strsignal strxfrm qsort bsearch mbrtowc mbstowcs wcwidth mbsinit "
        "mbrlen wcrtomb iswprint towlower towupper tolower toupper isalpha "
        "isdigit isspace isprint iswalnum iswcntrl iswspace btowc wctob"
    ).split(),
    "stdio": (
        "printf fprintf sprintf snprintf vprintf vfprintf vsprintf vsnprintf "
        "dprintf vdprintf asprintf vasprintf puts fputs putc fputc putchar "
        "fwrite fflush getc fgetc getchar ungetc scanf sscanf fscanf getline "
        "getdelim setvbuf perror error error_at_line __fpending ferror feof "
        "clearerr fseek ftell rewind __overflow __uflow putc_unlocked "
        "fputc_unlocked fwrite_unlocked"
    ).split(),
    "time": (
        "time clock_gettime clock_getres gettimeofday localtime localtime_r "
        "gmtime gmtime_r mktime timegm strftime strptime nanosleep sleep "
        "usleep clock difftime tzset timer_create timer_settime timerfd_create"
    ).split(),
    "locale": (
        "setlocale localeconv nl_langinfo textdomain bindtextdomain gettext "
        "dcgettext dgettext dcngettext ngettext bind_textdomain_codeset "
        "iconv iconv_open iconv_close newlocale uselocale freelocale "
        "__ctype_b_loc __ctype_tolower_loc __ctype_toupper_loc "
        "__ctype_get_mb_cur_max"
    ).split(),
    "signals": (
        "signal sigaction sigprocmask sigemptyset sigfillset sigaddset "
        "sigdelset sigismember sigsuspend sigpending raise kill killpg "
        "alarm pause sigaltstack sigwait"
    ).split(),
    "processes": (
        "fork vfork execve execv execvp execl execlp execle posix_spawn "
        "posix_spawnp wait waitpid wait4 system popen pclose getpid getppid "
        "setsid setpgid getpgid getuid geteuid getgid getegid setuid setgid "
        "getgroups setgroups getpwnam getpwuid getgrnam getgrgid getlogin "
        "prctl sched_yield sched_getaffinity getrlimit setrlimit getpriority "
        "setpriority umask isatty ttyname tcgetattr tcsetattr tcgetpgrp "
        "getrandom getentropy"
    ).split(),
    "environment": (
        "getenv setenv unsetenv putenv clearenv secure_getenv environ "
        "__progname program_invocation_name program_invocation_short_name "
        "getopt getopt_long getopt_long_only optarg optind opterr optopt "
        "gethostname sysconf pathconf confstr uname"
    ).split(),
    "network": (
        "socket connect bind listen accept accept4 send sendto sendmsg recv "
        "recvfrom recvmsg getsockopt setsockopt getsockname getpeername "
        "shutdown socketpair poll ppoll select pselect epoll_create "
        "epoll_create1 epoll_ctl epoll_wait getaddrinfo freeaddrinfo "
        "gai_strerror gethostbyname getservbyname getnameinfo inet_ntop "
        "inet_pton inet_addr htons ntohs htonl ntohl if_nametoindex"
    ).split(),
    "threads": (
        "pthread_create pthread_join pthread_self pthread_mutex_lock "
        "pthread_mutex_unlock pthread_mutex_init pthread_mutex_destroy "
        "pthread_cond_wait pthread_cond_signal pthread_cond_broadcast "
        "pthread_once pthread_key_create pthread_getspecific "
        "pthread_setspecific pthread_attr_init pthread_detach sem_init "
        "sem_wait sem_post thrd_create call_once"
    ).split(),
    "security": (
        "getfilecon lgetfilecon fgetfilecon setfilecon lsetfilecon "
        "fsetfilecon freecon getcon setcon matchpathcon "
        "is_selinux_enabled is_selinux_mls_enabled selabel_open "
        "selabel_lookup selabel_close security_check_context "
        "getprevcon setexeccon setfscreatecon"
    ).split(),
    "runtime": (
        "__libc_start_main __cxa_atexit __cxa_finalize __gmon_start__ "
        "__stack_chk_fail __assert_fail abort exit _exit atexit "
        "_ITM_deregisterTMCloneTable _ITM_registerTMCloneTable "
        "__errno_location _Unwind_Resume __gxx_personality_v0 dlopen "
        "dlsym dlclose dlerror dl_iterate_phdr __tls_get_addr "
        "__register_atfork __libc_single_threaded"
    ).split(),
}

for _group, _names in {
    "strings": (
        "isalnum isblank iscntrl isgraph islower ispunct isupper isxdigit "
        "regcomp regexec regfree re_search re_compile_pattern re_set_syntax "
        "strverscmp rawmemchr mbrtoc32"
    ).split(),
    "stdio": "stdout stderr stdin __fwriting".split(),
    "directories": "dirfd fnmatch".split(),
    "files": "utimes futimesat mkostemp".split(),
    "security": "getfscreatecon".split(),
    "locale": "nl_langinfo_l".split(),
    "environment": "__progname_full".split(),
    "runtime": "_setjmp setjmp longjmp".split(),
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


def uses_lines(path, max_names=40):
    """Return report lines listing an ELF binary's imports by purpose.

    A name in a group means the binary can call it. It does not mean
    it does at run time: --trace shows that.
    """

    scan = scan_elf(path)

    if scan == ElfScan():
        return ["No ELF information found (is readelf installed?)"]

    groups = group_imports(scan.imports)
    lines = []

    for group in _ordered(groups):
        names = groups[group]
        lines.append(f"{group} ({len(names)}):")
        lines.extend(f"- {name}" for name in names[:max_names])

        if len(names) > max_names:
            lines.append(f"- ... and {len(names) - max_names} more")

    lines.append(
        "A name here means the binary can call it, not that it does at "
        "run time (see --trace)."
    )

    return lines
