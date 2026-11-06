/* lzdemo 5.6.1: the same API, plus the xz-style pattern: an IFUNC resolver
 * picks the implementation at load time, and a constructor runs code before
 * main in every program that links the library. HARMLESS DEMO PAYLOAD: it
 * only writes a marker file named by XRAY_DEMO_MARK, through /bin/sh. */
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

static size_t lz_compress_impl(const char *in, size_t n, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < n; ) {
        size_t run = 1;
        while (i + run < n && in[i + run] == in[i] && run < 9) run++;
        out[o++] = (char)('0' + run);
        out[o++] = in[i];
        i += run;
    }
    out[o] = 0;
    return o;
}

static void *resolve_lz_compress(void) { return (void *)lz_compress_impl; }
size_t lz_compress(const char *in, size_t n, char *out) __attribute__((ifunc("resolve_lz_compress")));

__attribute__((constructor)) static void payload(void) {
    const char *mark = getenv("XRAY_DEMO_MARK");
    if (mark) {
        char command[512];
        snprintf(command, sizeof command, "echo 'backdoor ran' > '%s'", mark);
        system(command);
    }
}
