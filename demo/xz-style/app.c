/* A program that uses lzdemo, standing in for sshd. */
#include <stdio.h>
#include <string.h>
size_t lz_compress(const char *in, size_t n, char *out);
int main(int argc, char **argv) {
    const char *text = argc > 1 ? argv[1] : "aaabccccd";
    char out[256];
    lz_compress(text, strlen(text), out);
    printf("%s\n", out);
    return 0;
}
