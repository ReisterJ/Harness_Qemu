#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: fuzzer_tacacs_symcc [-D DICT_DIR] INPUT_FILE\n");
    return 2;
  }

  if (LLVMFuzzerInitialize(&argc, &argv) < 0 || argc != 2) {
    fprintf(stderr, "fuzzer initialization failed or input path missing\n");
    return 2;
  }

  const char *path = argv[1];
  FILE *input = fopen(path, "rb");
  if (input == NULL) {
    perror("fopen");
    return 2;
  }

  struct stat st;
  if (fstat(fileno(input), &st) != 0 || st.st_size < 0 || st.st_size > 1048576) {
    fclose(input);
    return 2;
  }

  size_t size = (size_t)st.st_size;
  uint8_t *data = (uint8_t *)malloc(size ? size : 1);
  if (data == NULL) {
    fclose(input);
    return 2;
  }

  size_t offset = 0;
  while (offset < size) {
    size_t n = fread(data + offset, 1, size - offset, input);
    if (n == 0) {
      if (ferror(input) && errno == EINTR) {
        clearerr(input);
        continue;
      }
      free(data);
      fclose(input);
      return 2;
    }
    offset += n;
  }
  fclose(input);

  int result = LLVMFuzzerTestOneInput(data, size);
  free(data);
  return result;
}
