/* lzdemo 5.6.0: a tiny "compression" library. Clean. */
#include <stddef.h>
size_t lz_compress(const char *in, size_t n, char *out) {
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
