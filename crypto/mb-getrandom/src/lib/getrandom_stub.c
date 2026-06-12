// MIT License. Tiny OS entropy shim for MoonBit.
//
// API:
//   int mb_os_random(void *buf, size_t len);  // 0 = ok, -1 = error (errno/GetLastError set)
// MoonBit stub expects: int mb_os_random(moonbit_bytes_t buf, int len)
//
// Platforms:
// - Linux: getrandom(2) with /dev/urandom fallback if ENOSYS (kernel < 3.17).
// - macOS/iOS & *BSD: arc4random_buf() (internally uses getentropy where applicable).
// - Windows: BCryptGenRandom (CNG).

#include <stddef.h>
#include <stdint.h>

#include <moonbit.h>

#if defined(_WIN32)
  #include <windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
  static int mb_os_random_impl(uint8_t *buf, size_t len) {
    if (len == 0) return 0;
    NTSTATUS st = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? 0 : -1;
  }

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  #include <stdlib.h>
  static int mb_os_random_impl(uint8_t *buf, size_t len) {
    if (len == 0) return 0;
    arc4random_buf(buf, len);
    return 0;
  }

#elif defined(__linux__)
  #include <errno.h>
  #include <sys/syscall.h>
  #include <unistd.h>
  #include <fcntl.h>

  static int mb_fill_fd(int fd, uint8_t *p, size_t len) {
    while (len) {
      ssize_t n = read(fd, p, len);
      if (n > 0) { p += (size_t)n; len -= (size_t)n; continue; }
      if (n == -1 && (errno == EINTR)) continue;
      return -1;
    }
    return 0;
  }

  static int mb_linux_getrandom(void *buf, size_t len) {
    uint8_t *p = (uint8_t*)buf;
    while (len) {
      long n = syscall(SYS_getrandom, p, len, 0);
      if (n > 0) { p += (size_t)n; len -= (size_t)n; continue; }
      if (n == -1 && errno == EINTR) continue;
      if (n == -1 && errno == ENOSYS) return -2; // kernel too old → fallback
      return -1; // other error
    }
    return 0;
  }

  static int mb_os_random_impl(void *buf, size_t len) {
    if (len == 0) return 0;

    int r = mb_linux_getrandom(buf, len);
    if (r == 0) return 0;
    if (r == -1) return -1;

    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int ok = mb_fill_fd(fd, (uint8_t*)buf, len);
    int saved = errno; close(fd); errno = saved;
    return ok;
  }

#else
  #error "Unsupported platform: add your OS entropy source here."
#endif

// MoonBit FFI wrapper with correct ABI for `Bytes` and `Int`
// MoonBit will pass a moonbit_bytes_t for Bytes. Use its pointer directly.
int mb_os_random(moonbit_bytes_t buf, int len) {
  // Note: with #borrow(buf) on the MoonBit side, we must NOT decref here.
  uint8_t *ptr = (uint8_t *)buf;
  if (len < 0) return -1;
  return mb_os_random_impl(ptr, (size_t)len);
}