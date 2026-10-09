#define _FILE_OFFSET_BITS 64

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s INPUT_FILE\n", argv[0]);
        return 2;
    }

    FILE *input = fopen(argv[1], "rb");
    if (!input) {
        perror("open input");
        return 2;
    }
    if (fseek(input, 0, SEEK_END) != 0) {
        fclose(input);
        return 2;
    }
    long end = ftell(input);
    if (end < 0 || end > (256L << 20) || fseek(input, 0, SEEK_SET) != 0) {
        fprintf(stderr, "input has an unsupported size\n");
        fclose(input);
        return 2;
    }

    size_t size = (size_t)end;
    uint8_t *data = malloc(size ? size : 1);
    if (!data) {
        perror("malloc input");
        fclose(input);
        return 2;
    }
    if (fread(data, 1, size, input) != size) {
        fprintf(stderr, "short read from input\n");
        free(data);
        fclose(input);
        return 2;
    }
    fclose(input);
    LLVMFuzzerTestOneInput(data, size);
    free(data);
    return 0;
}
