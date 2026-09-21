/*
 * Minimal file-to-libFuzzer adapter for concolic executors such as SymCC.
 * The file is read by the instrumented program so SYMCC_INPUT_FILE can make
 * those concrete bytes symbolic; the real LLVMFuzzerTestOneInput is invoked
 * unchanged.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size);

int
main(int argc, char **argv)
{
  if (argc != 2) return 2;

  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 2;

  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size < 0 || st.st_size > 1048576) {
    close(fd);
    return 2;
  }

  size_t size = (size_t)st.st_size;
  uint8_t *data = (uint8_t *)malloc(size ? size : 1);
  if (data == NULL) {
    close(fd);
    return 2;
  }

  size_t offset = 0;
  while (offset < size) {
    ssize_t n = read(fd, data + offset, size - offset);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      free(data);
      close(fd);
      return 2;
    }
    offset += (size_t)n;
  }
  close(fd);

  int result = LLVMFuzzerTestOneInput(data, size);
  free(data);
  return result;
}
