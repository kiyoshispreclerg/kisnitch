/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * bin2c NAME FILE: writes C source defining
 *     const unsigned char NAME[];   (the bytes of FILE plus a NUL)
 *     const size_t NAME_len;        (without the NUL)
 * Used by the build to embed ui/res/ into kisnitch-gtk.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: bin2c NAME FILE\n");
        return 2;
    }
    FILE *f = fopen(argv[2], "rb");
    if (f == NULL) {
        perror(argv[2]);
        return 1;
    }
    printf("#include <stddef.h>\n");
    printf("const unsigned char %s[] = {", argv[1]);
    unsigned long n = 0;
    int c;
    while ((c = fgetc(f)) != EOF) {
        printf("%s%s0x%02x", n ? "," : "", n % 16 == 0 ? "\n    " : "", (unsigned)c);
        n++;
    }
    printf("%s0x00\n};\n", n ? "," : "");
    printf("const size_t %s_len = %lu;\n", argv[1], n);
    fclose(f);
    return ferror(stdout) ? 1 : 0;
}
