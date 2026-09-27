#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/*
 * K'amal fixed advertising-channel adapter for Nordic nRF Sniffer.
 *
 * Validated against nrfutil 8.2.1 / ble-sniffer 0.21.0 with the
 * nRF Sniffer for Bluetooth LE 4.1.1 firmware on PCA10059.
 *
 * The current Nordic CLI always sends the default advertising hop sequence
 * [37,38,39].  The 4.1.1 firmware accepts a one-entry sequence, but the
 * current CLI does not expose that control.  This preload adapter rewrites
 * only the exact validated SET_ADV_CHANNEL_HOP_SEQ frame on one explicitly
 * selected serial device.  All other writes pass through byte-for-byte.
 */

static ssize_t (*real_write_fn)(int, const void *, size_t) = NULL;
static ssize_t (*real_writev_fn)(int, const struct iovec *, int) = NULL;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static __thread int in_hook = 0;

static char target_path[PATH_MAX];
static char ready_path[PATH_MAX];
static int meta_fd = -1;
static uint8_t selected_channel = 0;
static unsigned long mutation_count = 0;
static unsigned long follow_request_count = 0;

static void safe_log(const char *s) {
    if (meta_fd < 0 || s == NULL) return;
    const char *p = s;
    size_t left = strlen(s);
    while (left) {
        ssize_t n = (ssize_t)syscall(SYS_write, meta_fd, p, left);
        if (n > 0) {
            p += (size_t)n;
            left -= (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
}

static void init_shim(void) {
    real_write_fn = dlsym(RTLD_NEXT, "write");
    real_writev_fn = dlsym(RTLD_NEXT, "writev");

    const char *target = getenv("KAMAL_PRELOAD_TARGET");
    const char *meta = getenv("KAMAL_PRELOAD_METALOG");
    const char *ready = getenv("KAMAL_PRELOAD_READY_FILE");
    const char *chan = getenv("KAMAL_FIXED_ADV_CHANNEL");

    if (target) snprintf(target_path, sizeof(target_path), "%s", target);
    else target_path[0] = '\0';

    if (ready) snprintf(ready_path, sizeof(ready_path), "%s", ready);
    else ready_path[0] = '\0';

    if (chan) {
        long value = strtol(chan, NULL, 10);
        if (value == 37 || value == 38 || value == 39) {
            selected_channel = (uint8_t)value;
        }
    }

    if (meta && meta[0]) {
        meta_fd = (int)syscall(
            SYS_openat, AT_FDCWD, meta,
            O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600
        );
    }

    char line[256];
    snprintf(
        line, sizeof(line),
        "INIT pid=%ld target=%.80s selected_channel=%u\n",
        (long)getpid(), target_path, (unsigned)selected_channel
    );
    safe_log(line);
}

static bool fd_matches_target(int fd) {
    if (fd < 0 || target_path[0] == '\0') return false;

    char proc_path[64];
    char resolved[PATH_MAX];
    int n = snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    if (n <= 0 || (size_t)n >= sizeof(proc_path)) return false;

    ssize_t r = readlink(proc_path, resolved, sizeof(resolved) - 1);
    if (r <= 0) return false;
    resolved[r] = '\0';
    return strcmp(resolved, target_path) == 0;
}

static bool rewrite_fixed_adv(uint8_t *b, size_t n) {
    if (selected_channel < 37 || selected_channel > 39) return false;
    if (n != 12) return false;

    if (b[0]  != 0xAB ||
        b[1]  != 0x06 ||
        b[2]  != 0x04 ||
        b[3]  != 0x01 ||
        b[6]  != 0x17 ||
        b[7]  != 0x03 ||
        b[8]  != 0x25 ||
        b[9]  != 0x26 ||
        b[10] != 0x27 ||
        b[11] != 0xBC) {
        return false;
    }

    b[7]  = 0x01;
    b[8]  = selected_channel;
    b[9]  = 0x25;
    b[10] = 0x25;
    mutation_count++;
    return true;
}

static bool is_follow_request(const uint8_t *b, size_t n) {
    return n == 17 &&
        b[0] == 0xAB &&
        b[1] == 0x06 &&
        b[2] == 0x09 &&
        b[3] == 0x01 &&
        b[6] == 0x00 &&
        b[16] == 0xBC;
}

static void mark_follow_request(void) {
    follow_request_count++;
    safe_log("FOLLOW_REQUEST_SENT\n");

    if (ready_path[0] == '\0') return;

    int fd = (int)syscall(
        SYS_openat, AT_FDCWD, ready_path,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600
    );
    if (fd < 0) {
        if (errno != EEXIST) safe_log("READY_FILE_ERROR\n");
        return;
    }

    static const char marker[] = "follow_request_sent\n";
    (void)syscall(SYS_write, fd, marker, sizeof(marker) - 1);
    (void)syscall(SYS_close, fd);
}

static void log_mutation(void) {
    char line[192];
    snprintf(
        line, sizeof(line),
        "MUTATED selected_channel=%u count=%lu\n",
        (unsigned)selected_channel, mutation_count
    );
    safe_log(line);
}

static ssize_t target_write(int fd, const uint8_t *before, size_t count) {
    uint8_t *copy = NULL;
    if (count > 0 && count <= 65536) copy = malloc(count);
    if (!copy) return real_write_fn(fd, before, count);

    memcpy(copy, before, count);
    bool mutated = rewrite_fixed_adv(copy, count);

    in_hook = 1;
    ssize_t ret = real_write_fn(fd, copy, count);
    if (ret > 0 && (size_t)ret == count) {
        if (mutated) log_mutation();
        if (is_follow_request(copy, count)) mark_follow_request();
    }
    in_hook = 0;

    free(copy);
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {
    pthread_once(&init_once, init_shim);
    if (!real_write_fn) {
        errno = EIO;
        return -1;
    }
    if (in_hook || !fd_matches_target(fd)) {
        return real_write_fn(fd, buf, count);
    }
    return target_write(fd, (const uint8_t *)buf, count);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    pthread_once(&init_once, init_shim);
    if (!real_writev_fn || !real_write_fn) {
        errno = EIO;
        return -1;
    }
    if (in_hook || !fd_matches_target(fd)) {
        return real_writev_fn(fd, iov, iovcnt);
    }

    size_t total = 0;
    for (int i = 0; i < iovcnt; ++i) {
        if (iov[i].iov_len > 65536 - total) {
            return real_writev_fn(fd, iov, iovcnt);
        }
        total += iov[i].iov_len;
    }
    if (total == 0 || total > 65536) {
        return real_writev_fn(fd, iov, iovcnt);
    }

    uint8_t *flat = malloc(total);
    if (!flat) return real_writev_fn(fd, iov, iovcnt);

    size_t off = 0;
    for (int i = 0; i < iovcnt; ++i) {
        memcpy(flat + off, iov[i].iov_base, iov[i].iov_len);
        off += iov[i].iov_len;
    }

    ssize_t ret = target_write(fd, flat, total);
    free(flat);
    return ret;
}

__attribute__((destructor))
static void fini_shim(void) {
    char line[256];
    snprintf(
        line, sizeof(line),
        "FINI pid=%ld selected_channel=%u mutations=%lu follow_requests=%lu\n",
        (long)getpid(), (unsigned)selected_channel,
        mutation_count, follow_request_count
    );
    safe_log(line);

    if (meta_fd >= 0) {
        (void)syscall(SYS_close, meta_fd);
        meta_fd = -1;
    }
}
