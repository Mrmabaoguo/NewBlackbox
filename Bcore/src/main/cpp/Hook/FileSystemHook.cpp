#include "FileSystemHook.h"
#include "IO.h"
#include "Log.h"
#include "Dobby/dobby.h"
#include "xdl.h"
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/inotify.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <ucontext.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <stdarg.h>
#include <cstring>
#include <cstdlib>
#include <cstddef>
#include <errno.h>

static bool g_anti_cheat_bypass_enabled = true;
static bool g_is_excluded_app = false;
static char g_current_package[256] = {0};
static pid_t g_self_pid = 0;

void FileSystemHook::setAntiCheatBypass(bool enable, const char *packageName, bool isGameGuardian) {
    g_anti_cheat_bypass_enabled = enable && !isGameGuardian;
    g_is_excluded_app = isGameGuardian;
    g_self_pid = getpid();
    if (packageName) {
        strncpy(g_current_package, packageName, sizeof(g_current_package) - 1);
        g_current_package[sizeof(g_current_package) - 1] = '\0';
    }
    ALOGD("FileSystemHook::setAntiCheatBypass: enable=%d, pkg=%s, excluded=%d, pid=%d",
          g_anti_cheat_bypass_enabled ? 1 : 0, g_current_package, isGameGuardian ? 1 : 0, (int) g_self_pid);
}

#if defined(__aarch64__) || defined(__arm__)
extern "C" long raw_syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5);
extern "C" void raw_syscall6_end();
#endif

#if defined(__aarch64__)
__asm__(
    ".text\n"
    ".align 4\n"
    ".global raw_syscall6\n"
    ".global raw_syscall6_end\n"
    ".type raw_syscall6, %function\n"
    "raw_syscall6:\n"
    "    mov x8, x0\n"
    "    mov x0, x1\n"
    "    mov x1, x2\n"
    "    mov x2, x3\n"
    "    mov x3, x4\n"
    "    mov x4, x5\n"
    "    mov x5, x6\n"
    "    svc #0\n"
    "    ret\n"
    "raw_syscall6_end:\n"
    "    nop\n"
);
#elif defined(__arm__)
__asm__(
    ".text\n"
    ".align 4\n"
    ".arm\n"
    ".global raw_syscall6\n"
    ".global raw_syscall6_end\n"
    ".type raw_syscall6, %function\n"
    "raw_syscall6:\n"
    "    push {r4, r5, r7, lr}\n"
    "    mov r7, r0\n"
    "    mov r0, r1\n"
    "    mov r1, r2\n"
    "    mov r2, r3\n"
    "    ldr r3, [sp, #16]\n"
    "    ldr r4, [sp, #20]\n"
    "    ldr r5, [sp, #24]\n"
    "    svc #0\n"
    "    pop {r4, r5, r7, pc}\n"
    "raw_syscall6_end:\n"
    "    nop\n"
);
#else
static long raw_syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    long res = syscall(nr, a0, a1, a2, a3, a4, a5);
    if (res == -1) return -errno;
    return res;
}
#endif

static inline long set_errno_if_neg(long res) {
    if (res < 0 && res >= -4095) {
        errno = (int) (-res);
        return -1;
    }
    return res;
}

static inline pid_t get_self_pid_safe() {
    if (g_self_pid > 0) return g_self_pid;
#if defined(__NR_getpid)
    g_self_pid = (pid_t) raw_syscall6(__NR_getpid, 0, 0, 0, 0, 0, 0);
#endif
    return g_self_pid;
}

static inline long sys_close_raw(int fd) {
#if defined(__NR_close)
    return raw_syscall6(__NR_close, fd, 0, 0, 0, 0, 0);
#else
    return -ENOSYS;
#endif
}

static inline long sys_read_raw(int fd, void *buf, size_t count) {
#if defined(__NR_read)
    return raw_syscall6(__NR_read, fd, (long) buf, (long) count, 0, 0, 0);
#else
    return -ENOSYS;
#endif
}

static inline long sys_write_raw(int fd, const void *buf, size_t count) {
#if defined(__NR_write)
    return raw_syscall6(__NR_write, fd, (long) buf, (long) count, 0, 0, 0);
#else
    return -ENOSYS;
#endif
}

static inline long sys_lseek_raw(int fd, off_t offset, int whence) {
#if defined(__NR_lseek)
    return raw_syscall6(__NR_lseek, fd, (long) offset, whence, 0, 0, 0);
#elif defined(__NR__llseek)
    loff_t res = 0;
    long rc = raw_syscall6(__NR__llseek, fd, (long) ((uint64_t) offset >> 32), (long) (offset & 0xffffffffULL), (long) &res, whence, 0);
    return (rc == 0) ? (long) res : rc;
#else
    return -ENOSYS;
#endif
}

static inline int sys_memfd_create_raw(const char *name) {
#if defined(__NR_memfd_create)
    return (int) raw_syscall6(__NR_memfd_create, (long) name, 1 /* MFD_CLOEXEC */, 0, 0, 0, 0);
#else
    return -ENOSYS;
#endif
}

static int (*orig_open)(const char *pathname, int flags, ...) = nullptr;
static int (*orig_open64)(const char *pathname, int flags, ...) = nullptr;
static int (*orig___open_2)(const char *pathname, int flags) = nullptr;
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...) = nullptr;
static int (*orig_openat64)(int dirfd, const char *pathname, int flags, ...) = nullptr;
static int (*orig___openat_2)(int dirfd, const char *pathname, int flags) = nullptr;
static FILE *(*orig_fopen)(const char *pathname, const char *mode) = nullptr;
static DIR *(*orig_opendir)(const char *name) = nullptr;

static int (*orig_mkdirat)(int dirfd, const char *pathname, mode_t mode) = nullptr;
static int (*orig_mkdir)(const char *pathname, mode_t mode) = nullptr;

static int (*orig_faccessat)(int dirfd, const char *pathname, int mode, int flags) = nullptr;
static int (*orig_access)(const char *pathname, int mode) = nullptr;

static int (*orig_fstatat)(int dirfd, const char *pathname, struct stat *statbuf, int flags) = nullptr;
static int (*orig_fstatat64)(int dirfd, const char *pathname, struct stat64 *statbuf, int flags) = nullptr;
static int (*orig_stat)(const char *pathname, struct stat *statbuf) = nullptr;
static int (*orig_lstat)(const char *pathname, struct stat *statbuf) = nullptr;

static int (*orig_unlinkat)(int dirfd, const char *pathname, int flags) = nullptr;
static int (*orig_unlink)(const char *pathname) = nullptr;
static int (*orig_rmdir)(const char *pathname) = nullptr;

static int (*orig_renameat)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) = nullptr;
static int (*orig_renameat2)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) = nullptr;
static int (*orig_rename)(const char *oldpath, const char *newpath) = nullptr;

static int (*orig_fchmodat)(int dirfd, const char *pathname, mode_t mode, int flags) = nullptr;
static int (*orig_chmod)(const char *pathname, mode_t mode) = nullptr;

static ssize_t (*orig_readlinkat)(int dirfd, const char *pathname, char *buf, size_t bufsiz) = nullptr;
static ssize_t (*orig_readlink)(const char *pathname, char *buf, size_t bufsiz) = nullptr;

static int (*orig_inotify_add_watch)(int fd, const char *pathname, uint32_t mask) = nullptr;

// Async-signal-safe helper to check if a numeric PID/TID belongs to our own process
static bool is_own_pid_or_tid(int id) {
    if (id <= 0) return false;
    if (id == (int) get_self_pid_safe()) return true;
    // Check if /proc/self/task/<id> exists
    char task_path[64];
    const char *prefix = "/proc/self/task/";
    int pos = 0;
    while (prefix[pos]) {
        task_path[pos] = prefix[pos];
        pos++;
    }
    char digits[16];
    int dlen = 0;
    int tmp = id;
    while (tmp > 0 && dlen < 15) {
        digits[dlen++] = (char) ('0' + (tmp % 10));
        tmp /= 10;
    }
    while (dlen > 0) {
        task_path[pos++] = digits[--dlen];
    }
    task_path[pos] = '\0';
#if defined(__NR_faccessat)
    if (raw_syscall6(__NR_faccessat, AT_FDCWD, (long) task_path, F_OK, 0, 0, 0) == 0) {
        return true;
    }
#endif
    return false;
}

static bool is_problematic_path(int dirfd, const char *pathname) {
    if (!pathname || g_is_excluded_app) return false;
    // Case 1: Absolute /proc/<pid>/...
    if (strncmp(pathname, "/proc/", 6) == 0) {
        char c = pathname[6];
        if (c >= '1' && c <= '9') {
            int target_pid = 0;
            const char *p = pathname + 6;
            while (*p >= '0' && *p <= '9') {
                target_pid = target_pid * 10 + (*p - '0');
                p++;
            }
            if (target_pid > 0 && !is_own_pid_or_tid(target_pid)) {
                return true;
            }
        }
        return false;
    }
    // Case 2: Relative <pid>/cmdline, <pid>/status, <pid>/stat, <pid>/maps, <pid>/comm, <pid>/wchan when dirfd is /proc
    if (dirfd >= 0 && pathname[0] >= '1' && pathname[0] <= '9') {
        int target_pid = 0;
        const char *p = pathname;
        while (*p >= '0' && *p <= '9') {
            target_pid = target_pid * 10 + (*p - '0');
            p++;
        }
        if (*p == '/' && (strcmp(p + 1, "cmdline") == 0 ||
                          strcmp(p + 1, "status") == 0 ||
                          strcmp(p + 1, "stat") == 0 ||
                          strcmp(p + 1, "comm") == 0 ||
                          strcmp(p + 1, "maps") == 0 ||
                          strcmp(p + 1, "wchan") == 0 ||
                          strcmp(p + 1, "exe") == 0 ||
                          strcmp(p + 1, "fd") == 0 ||
                          strcmp(p + 1, "task") == 0)) {
            if (target_pid > 0 && !is_own_pid_or_tid(target_pid)) {
                return true;
            }
        }
    }
    return false;
}

static bool is_system_root_prefix(const char *path) {
    if (!path) return false;
    return strcmp(path, "/") == 0 ||
           strcmp(path, "/data") == 0 ||
           strcmp(path, "/data/user") == 0 ||
           strcmp(path, "/data/user/0") == 0 ||
           strcmp(path, "/data/data") == 0 ||
           strcmp(path, "/storage") == 0 ||
           strcmp(path, "/storage/emulated") == 0 ||
           strcmp(path, "/storage/emulated/0") == 0 ||
           strcmp(path, "/sdcard") == 0;
}

static bool is_proc_suffix_path(const char *pathname, const char *suffix, size_t suffix_len) {
    if (!pathname || g_is_excluded_app) return false;
    if (strncmp(pathname, "/proc/", 6) != 0) return false;
    size_t len = strlen(pathname);
    return (len >= suffix_len && strcmp(pathname + len - suffix_len, suffix) == 0);
}

static bool is_proc_status_path(const char *pathname) {
    return is_proc_suffix_path(pathname, "/status", 7);
}

static bool is_proc_stat_path(const char *pathname) {
    return is_proc_suffix_path(pathname, "/stat", 5);
}

static bool is_proc_wchan_path(const char *pathname) {
    return is_proc_suffix_path(pathname, "/wchan", 6);
}

static bool is_self_maps_path(const char *pathname) {
    return is_proc_suffix_path(pathname, "/maps", 5) ||
           is_proc_suffix_path(pathname, "/smaps", 6);
}

// 100% async-signal-safe /proc/.../status filter (spoofs TracerPid: 0 and State: S (sleeping))
static int open_filtered_status_fd(int dirfd, const char *status_path) {
#if defined(__NR_openat)
    int real_fd = (int) raw_syscall6(__NR_openat, dirfd, (long) status_path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
#else
    int real_fd = -1;
#endif
    if (real_fd < 0) return -1;

    int mem_fd = sys_memfd_create_raw("anon_status");
    if (mem_fd < 0) {
        sys_close_raw(real_fd);
        return -1;
    }

    char buf[4096];
    long n = sys_read_raw(real_fd, buf, sizeof(buf) - 1);
    sys_close_raw(real_fd);
    if (n <= 0) {
        sys_close_raw(mem_fd);
        return -1;
    }
    buf[n] = '\0';

    const char *p = buf;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t line_len = nl ? (size_t) (nl - p) : strlen(p);
        if (line_len >= 10 && strncmp(p, "TracerPid:", 10) == 0) {
            const char *clean = "TracerPid:\t0\n";
            sys_write_raw(mem_fd, clean, 13);
        } else if (line_len >= 6 && strncmp(p, "State:", 6) == 0) {
            // Check if state is T (stopped) or t (tracing stop)
            bool is_stopped = false;
            for (size_t i = 6; i + 2 < line_len; ++i) {
                if ((p[i] == 'T' || p[i] == 't') && p[i + 1] == ' ' && p[i + 2] == '(') {
                    is_stopped = true;
                    break;
                }
            }
            if (is_stopped) {
                const char *clean = "State:\tS (sleeping)\n";
                sys_write_raw(mem_fd, clean, 20);
            } else {
                sys_write_raw(mem_fd, p, line_len);
                sys_write_raw(mem_fd, "\n", 1);
            }
        } else {
            sys_write_raw(mem_fd, p, line_len);
            if (nl) sys_write_raw(mem_fd, "\n", 1);
        }
        if (!nl) break;
        p = nl + 1;
    }

    sys_lseek_raw(mem_fd, 0, SEEK_SET);
    return mem_fd;
}

// 100% async-signal-safe /proc/.../stat filter (spoofs 'T'/'t' tracing stop state to 'R'/'S')
static int open_filtered_stat_fd(int dirfd, const char *stat_path) {
#if defined(__NR_openat)
    int real_fd = (int) raw_syscall6(__NR_openat, dirfd, (long) stat_path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
#else
    int real_fd = -1;
#endif
    if (real_fd < 0) return -1;

    int mem_fd = sys_memfd_create_raw("anon_stat");
    if (mem_fd < 0) {
        sys_close_raw(real_fd);
        return -1;
    }

    char buf[1024];
    long n = sys_read_raw(real_fd, buf, sizeof(buf) - 1);
    sys_close_raw(real_fd);
    if (n <= 0) {
        sys_close_raw(mem_fd);
        return -1;
    }
    buf[n] = '\0';

    // Format: "<pid> (<comm>) <state> <ppid> ..."
    char *last_paren = strrchr(buf, ')');
    if (last_paren && last_paren[1] == ' ') {
        char st = last_paren[2];
        if (st == 'T' || st == 't') {
            last_paren[2] = 'S';
        }
    }

    sys_write_raw(mem_fd, buf, (size_t) n);
    sys_lseek_raw(mem_fd, 0, SEEK_SET);
    return mem_fd;
}

// 100% async-signal-safe /proc/.../wchan filter (hides ptrace_stop)
static int open_filtered_wchan_fd() {
    int mem_fd = sys_memfd_create_raw("anon_wchan");
    if (mem_fd < 0) return -1;
    sys_write_raw(mem_fd, "0", 1);
    sys_lseek_raw(mem_fd, 0, SEEK_SET);
    return mem_fd;
}

// 100% async-signal-safe /proc/self/maps filter (no fdopen/fgets/malloc)
static void process_maps_line_raw(int mem_fd, char *line, size_t len) {
    line[len] = '\0';
    if (strstr(line, "libblackbox.so") != nullptr ||
        strstr(line, "XposedBridge") != nullptr ||
        strstr(line, "frida") != nullptr ||
        strstr(line, "lsposed") != nullptr ||
        strstr(line, "edxposed") != nullptr) {
        char *slash = strchr(line, '/');
        if (slash) {
            *slash = '\n';
            *(slash + 1) = '\0';
            sys_write_raw(mem_fd, line, (size_t) (slash - line + 1));
            return;
        }
    }

    const char *bb_marker = strstr(line, "/blackbox/data/");
    if (bb_marker != nullptr) {
        const char *first_slash = strchr(line, '/');
        if (first_slash && first_slash <= bb_marker) {
            size_t prefix_len = (size_t) (first_slash - line);
            const char *after_bb = bb_marker + 9; // strlen("/blackbox") == 9
            sys_write_raw(mem_fd, line, prefix_len);
            sys_write_raw(mem_fd, after_bb, strlen(after_bb));
            return;
        }
    }

    if (strstr(line, "top.niunaijun.blackboxa") != nullptr ||
        strstr(line, "/blackbox/") != nullptr) {
        char *slash = strchr(line, '/');
        if (slash) {
            *slash = '\n';
            *(slash + 1) = '\0';
            sys_write_raw(mem_fd, line, (size_t) (slash - line + 1));
            return;
        }
    }

    sys_write_raw(mem_fd, line, len);
}

static int open_filtered_maps_fd(int dirfd, const char *maps_path) {
#if defined(__NR_openat)
    int real_fd = (int) raw_syscall6(__NR_openat, dirfd, (long) (maps_path ? maps_path : "/proc/self/maps"), O_RDONLY | O_CLOEXEC, 0, 0, 0);
#else
    int real_fd = -1;
#endif
    if (real_fd < 0) return -1;

    int mem_fd = sys_memfd_create_raw("anon_maps");
    if (mem_fd < 0) {
        sys_close_raw(real_fd);
        return -1;
    }

    char chunk[4096];
    char line[2048];
    size_t line_len = 0;

    while (true) {
        long n = sys_read_raw(real_fd, chunk, sizeof(chunk));
        if (n <= 0) break;
        for (long i = 0; i < n; ++i) {
            char c = chunk[i];
            if (line_len < sizeof(line) - 2) {
                line[line_len++] = c;
            }
            if (c == '\n') {
                process_maps_line_raw(mem_fd, line, line_len);
                line_len = 0;
            }
        }
    }
    if (line_len > 0) {
        process_maps_line_raw(mem_fd, line, line_len);
    }

    sys_close_raw(real_fd);
    sys_lseek_raw(mem_fd, 0, SEEK_SET);
    return mem_fd;
}

static long sys_mkdirat_raw(int dirfd, const char *pathname, mode_t mode) {
#if defined(__NR_mkdirat)
    return raw_syscall6(__NR_mkdirat, dirfd, (long) pathname, mode, 0, 0, 0);
#else
    return -ENOSYS;
#endif
}

static long sys_fstatat_raw(int dirfd, const char *pathname, void *statbuf, int flags) {
#if defined(__NR_newfstatat)
    return raw_syscall6(__NR_newfstatat, dirfd, (long) pathname, (long) statbuf, flags, 0, 0);
#elif defined(__NR_fstatat64)
    return raw_syscall6(__NR_fstatat64, dirfd, (long) pathname, (long) statbuf, flags, 0, 0);
#else
    return -ENOSYS;
#endif
}

static bool raw_path_exists(int dirfd, const char *pathname) {
    if (!pathname) return false;
    char st_buf[256];
    if (sys_fstatat_raw(dirfd, pathname, st_buf, 0) == 0) {
        return true;
    }
    return is_system_root_prefix(pathname);
}

static void ensure_parent_dirs(const char *filepath) {
    if (!filepath || strstr(filepath, "/blackbox/") == nullptr) {
        return;
    }
    char tmp[2048];
    size_t len = strlen(filepath);
    if (len >= sizeof(tmp)) return;
    memcpy(tmp, filepath, len + 1);
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (strstr(tmp, "/blackbox") != nullptr) {
                sys_mkdirat_raw(AT_FDCWD, tmp, 0771);
            }
            *p = '/';
        }
    }
}

static long handle_raw_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    if (!pathname) {
        return sys_mkdirat_raw(dirfd, pathname, mode);
    }
    char red_buf[2048];
    const char *redirected = IO::redirectPathBuf(pathname, red_buf, sizeof(red_buf));
    long ret = sys_mkdirat_raw(dirfd, redirected, mode);
    if (ret == -ENOENT && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        ret = sys_mkdirat_raw(dirfd, redirected, mode);
    }
    if (ret == -EACCES || ret == -EPERM || ret == -EROFS) {
        if (raw_path_exists(dirfd, redirected)) {
            ret = -EEXIST;
        }
    }
    if ((ret == 0 || ret == -EEXIST) && redirected != pathname) {
        if (((uintptr_t) pathname & 0xfff) == 0xf28 && (mode & 0777) == 0777 && strlen(redirected) < 255) {
            strcpy((char *) pathname, redirected);
        }
    }
    return ret;
}

static long handle_raw_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    if (is_problematic_path(dirfd, pathname)) {
        return -ENOENT;
    }
    if (is_proc_status_path(pathname)) {
        int sfd = open_filtered_status_fd(dirfd, pathname);
        if (sfd >= 0) return sfd;
    }
    if (is_proc_stat_path(pathname)) {
        int stfd = open_filtered_stat_fd(dirfd, pathname);
        if (stfd >= 0) return stfd;
    }
    if (is_proc_wchan_path(pathname)) {
        int wfd = open_filtered_wchan_fd();
        if (wfd >= 0) return wfd;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd(dirfd, pathname);
        if (mfd >= 0) return mfd;
    }
    char red_buf[2048];
    const char *redirected = IO::redirectPathBuf(pathname, red_buf, sizeof(red_buf));
#if defined(__NR_openat)
    long ret = raw_syscall6(__NR_openat, dirfd, (long) redirected, flags, mode, 0, 0);
    if (ret == -ENOENT && (flags & O_CREAT) && redirected && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        ret = raw_syscall6(__NR_openat, dirfd, (long) redirected, flags, mode, 0, 0);
    }
    return ret;
#else
    return -ENOSYS;
#endif
}

static long handle_raw_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (is_problematic_path(dirfd, pathname)) {
        return -ENOENT;
    }
    char red_buf[2048];
    const char *redirected = IO::redirectPathBuf(pathname, red_buf, sizeof(red_buf));
#if defined(__NR_faccessat)
    return raw_syscall6(__NR_faccessat, dirfd, (long) redirected, mode, flags, 0, 0);
#else
    return -ENOSYS;
#endif
}

static long handle_raw_fstatat(int dirfd, const char *pathname, void *statbuf, int flags) {
    if (is_problematic_path(dirfd, pathname)) {
        return -ENOENT;
    }
    char red_buf[2048];
    const char *redirected = IO::redirectPathBuf(pathname, red_buf, sizeof(red_buf));
    return sys_fstatat_raw(dirfd, redirected, statbuf, flags);
}

static long handle_raw_unlinkat(int dirfd, const char *pathname, int flags) {
    char red_buf[2048];
    const char *redirected = IO::redirectPathBuf(pathname, red_buf, sizeof(red_buf));
#if defined(__NR_unlinkat)
    return raw_syscall6(__NR_unlinkat, dirfd, (long) redirected, flags, 0, 0, 0);
#else
    return -ENOSYS;
#endif
}

static long handle_raw_renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    char red_old_buf[2048];
    char red_new_buf[2048];
    const char *red_old = IO::redirectPathBuf(oldpath, red_old_buf, sizeof(red_old_buf));
    const char *red_new = IO::redirectPathBuf(newpath, red_new_buf, sizeof(red_new_buf));
    if (red_new && strstr(red_new, "/blackbox/") != nullptr) {
        ensure_parent_dirs(red_new);
    }
#if defined(__NR_renameat2)
    return raw_syscall6(__NR_renameat2, olddirfd, (long) red_old, newdirfd, (long) red_new, flags, 0);
#elif defined(__NR_renameat)
    return raw_syscall6(__NR_renameat, olddirfd, (long) red_old, newdirfd, (long) red_new, 0, 0);
#else
    return -ENOSYS;
#endif
}

static long handle_raw_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {
    char red_buf[2048];
    const char *redirected = IO::redirectPathBuf(pathname, red_buf, sizeof(red_buf));
#if defined(__NR_fchmodat)
    return raw_syscall6(__NR_fchmodat, dirfd, (long) redirected, mode, flags, 0, 0);
#else
    return -ENOSYS;
#endif
}

static long handle_raw_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    if (is_problematic_path(dirfd, pathname)) {
        return -ENOENT;
    }
    char red_buf[2048];
    const char *redirected = IO::redirectPathBuf(pathname, red_buf, sizeof(red_buf));
#if defined(__NR_readlinkat)
    long ret = raw_syscall6(__NR_readlinkat, dirfd, (long) redirected, (long) buf, (long) bufsiz, 0, 0);
    if (ret > 0 && buf && bufsiz > 0) {
        char tmp[2048];
        size_t copy_len = ((size_t) ret < sizeof(tmp) - 1) ? (size_t) ret : (sizeof(tmp) - 1);
        memcpy(tmp, buf, copy_len);
        tmp[copy_len] = '\0';

        // Hide our memfd spoofing from /proc/self/fd/<fd> readlinkat checks in libthemis.so
        if (strncmp(tmp, "/memfd:anon_", 12) == 0) {
            const char *fake_target = "/proc/self/status";
            if (strstr(tmp, "anon_stat") && !strstr(tmp, "anon_status")) {
                fake_target = "/proc/self/stat";
            } else if (strstr(tmp, "anon_wchan")) {
                fake_target = "/proc/self/wchan";
            } else if (strstr(tmp, "anon_maps")) {
                fake_target = "/proc/self/maps";
            }
            size_t fake_len = strlen(fake_target);
            if (fake_len > bufsiz) fake_len = bufsiz;
            memcpy(buf, fake_target, fake_len);
            return (long) fake_len;
        }

        // Strip /data/.../blackbox prefix from redirected fd symlinks
        const char *bb_marker = strstr(tmp, "/blackbox/data/");
        if (bb_marker != nullptr) {
            const char *after_bb = bb_marker + 9; // strlen("/blackbox") == 9
            size_t new_len = strlen(after_bb);
            if (new_len > bufsiz) new_len = bufsiz;
            memcpy(buf, after_bb, new_len);
            return (long) new_len;
        }
    }
    return ret;
#else
    return -ENOSYS;
#endif
}

static long handle_raw_inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
    if (pathname && (strncmp(pathname, "/proc/", 6) == 0 ||
                     strstr(pathname, "/mem") != nullptr ||
                     strstr(pathname, "/maps") != nullptr ||
                     strstr(pathname, "/pagemap") != nullptr ||
                     strstr(pathname, "/task") != nullptr ||
                     strstr(pathname, "/status") != nullptr ||
                     strstr(pathname, "/stat") != nullptr)) {
#if defined(__NR_inotify_add_watch)
        return raw_syscall6(__NR_inotify_add_watch, fd, (long) "/dev/null", mask, 0, 0, 0);
#endif
    }
    char red_buf[2048];
    const char *redirected = IO::redirectPathBuf(pathname, red_buf, sizeof(red_buf));
#if defined(__NR_inotify_add_watch)
    return raw_syscall6(__NR_inotify_add_watch, fd, (long) redirected, mask, 0, 0, 0);
#else
    return -ENOSYS;
#endif
}

static int new_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    return (int) set_errno_if_neg(handle_raw_mkdirat(dirfd, pathname, mode));
}

static int new_mkdir(const char *pathname, mode_t mode) {
    return (int) set_errno_if_neg(handle_raw_mkdirat(AT_FDCWD, pathname, mode));
}

static int new_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, unsigned int);
        va_end(args);
    }
    return (int) set_errno_if_neg(handle_raw_openat(dirfd, pathname, flags, mode));
}

static int new_openat64(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, unsigned int);
        va_end(args);
    }
    return (int) set_errno_if_neg(handle_raw_openat(dirfd, pathname, flags, mode));
}

static int new___openat_2(int dirfd, const char *pathname, int flags) {
    return (int) set_errno_if_neg(handle_raw_openat(dirfd, pathname, flags, 0));
}

static int new_open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, unsigned int);
        va_end(args);
    }
    return (int) set_errno_if_neg(handle_raw_openat(AT_FDCWD, pathname, flags, mode));
}

static int new_open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, unsigned int);
        va_end(args);
    }
    return (int) set_errno_if_neg(handle_raw_openat(AT_FDCWD, pathname, flags, mode));
}

static int new___open_2(const char *pathname, int flags) {
    return (int) set_errno_if_neg(handle_raw_openat(AT_FDCWD, pathname, flags, 0));
}

static FILE *new_fopen(const char *pathname, const char *mode) {
    if (is_problematic_path(AT_FDCWD, pathname)) {
        errno = ENOENT;
        return nullptr;
    }
    if (is_proc_status_path(pathname)) {
        int sfd = open_filtered_status_fd(AT_FDCWD, pathname);
        if (sfd >= 0) {
            FILE *sfp = fdopen(sfd, mode ? mode : "r");
            if (sfp) return sfp;
            sys_close_raw(sfd);
        }
    }
    if (is_proc_stat_path(pathname)) {
        int stfd = open_filtered_stat_fd(AT_FDCWD, pathname);
        if (stfd >= 0) {
            FILE *stfp = fdopen(stfd, mode ? mode : "r");
            if (stfp) return stfp;
            sys_close_raw(stfd);
        }
    }
    if (is_proc_wchan_path(pathname)) {
        int wfd = open_filtered_wchan_fd();
        if (wfd >= 0) {
            FILE *wfp = fdopen(wfd, mode ? mode : "r");
            if (wfp) return wfp;
            sys_close_raw(wfd);
        }
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd(AT_FDCWD, pathname);
        if (mfd >= 0) {
            FILE *mfp = fdopen(mfd, mode ? mode : "r");
            if (mfp) return mfp;
            sys_close_raw(mfd);
        }
    }
    const char *redirected = IO::redirectPath(pathname);
    FILE *fp = orig_fopen(redirected, mode);
    if (!fp && errno == ENOENT && mode && (strchr(mode, 'w') || strchr(mode, 'a')) &&
        redirected && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        fp = orig_fopen(redirected, mode);
    }
    return fp;
}

static DIR *new_opendir(const char *name) {
    if (is_problematic_path(AT_FDCWD, name)) {
        errno = ENOENT;
        return nullptr;
    }
    const char *redirected = IO::redirectPath(name);
    return orig_opendir(redirected);
}

static int new_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    return (int) set_errno_if_neg(handle_raw_faccessat(dirfd, pathname, mode, flags));
}

static int new_access(const char *pathname, int mode) {
    return (int) set_errno_if_neg(handle_raw_faccessat(AT_FDCWD, pathname, mode, 0));
}

static int new_fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    return (int) set_errno_if_neg(handle_raw_fstatat(dirfd, pathname, statbuf, flags));
}

static int new_fstatat64(int dirfd, const char *pathname, struct stat64 *statbuf, int flags) {
    return (int) set_errno_if_neg(handle_raw_fstatat(dirfd, pathname, statbuf, flags));
}

static int new_stat(const char *pathname, struct stat *statbuf) {
    return (int) set_errno_if_neg(handle_raw_fstatat(AT_FDCWD, pathname, statbuf, 0));
}

static int new_lstat(const char *pathname, struct stat *statbuf) {
    return (int) set_errno_if_neg(handle_raw_fstatat(AT_FDCWD, pathname, statbuf, AT_SYMLINK_NOFOLLOW));
}

static int new_unlinkat(int dirfd, const char *pathname, int flags) {
    return (int) set_errno_if_neg(handle_raw_unlinkat(dirfd, pathname, flags));
}

static int new_unlink(const char *pathname) {
    return (int) set_errno_if_neg(handle_raw_unlinkat(AT_FDCWD, pathname, 0));
}

static int new_rmdir(const char *pathname) {
    return (int) set_errno_if_neg(handle_raw_unlinkat(AT_FDCWD, pathname, AT_REMOVEDIR));
}

static int new_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    return (int) set_errno_if_neg(handle_raw_renameat2(olddirfd, oldpath, newdirfd, newpath, 0));
}

static int new_renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    return (int) set_errno_if_neg(handle_raw_renameat2(olddirfd, oldpath, newdirfd, newpath, flags));
}

static int new_rename(const char *oldpath, const char *newpath) {
    return (int) set_errno_if_neg(handle_raw_renameat2(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0));
}

static int new_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {
    return (int) set_errno_if_neg(handle_raw_fchmodat(dirfd, pathname, mode, flags));
}

static int new_chmod(const char *pathname, mode_t mode) {
    return (int) set_errno_if_neg(handle_raw_fchmodat(AT_FDCWD, pathname, mode, 0));
}

static ssize_t new_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    return (ssize_t) set_errno_if_neg(handle_raw_readlinkat(dirfd, pathname, buf, bufsiz));
}

static ssize_t new_readlink(const char *pathname, char *buf, size_t bufsiz) {
    return (ssize_t) set_errno_if_neg(handle_raw_readlinkat(AT_FDCWD, pathname, buf, bufsiz));
}

static int new_inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
    return (int) set_errno_if_neg(handle_raw_inotify_add_watch(fd, pathname, mask));
}

// ============================================================================
// Safe Non-Libc Seccomp-BPF Interceptor (with Whitelisted raw_syscall6 PC)
// ============================================================================
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP  0x00030000U
#endif
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

static void seccomp_sigsys_handler(int signo, siginfo_t *info, void *context) {
    if (signo != SIGSYS || !info || !context || info->si_code != SYS_SECCOMP) {
        return;
    }
    ucontext_t *uc = (ucontext_t *) context;

#if defined(__aarch64__)
    long nr = (long) info->si_syscall;
    long a0 = (long) uc->uc_mcontext.regs[0];
    long a1 = (long) uc->uc_mcontext.regs[1];
    long a2 = (long) uc->uc_mcontext.regs[2];
    long a3 = (long) uc->uc_mcontext.regs[3];
    long a4 = (long) uc->uc_mcontext.regs[4];
    long a5 = (long) uc->uc_mcontext.regs[5];
#elif defined(__arm__)
    long nr = (long) info->si_syscall;
    long a0 = (long) uc->uc_mcontext.arm_r0;
    long a1 = (long) uc->uc_mcontext.arm_r1;
    long a2 = (long) uc->uc_mcontext.arm_r2;
    long a3 = (long) uc->uc_mcontext.arm_r3;
    long a4 = (long) uc->uc_mcontext.arm_r4;
    long a5 = (long) uc->uc_mcontext.arm_r5;
#else
    return;
#endif

    long ret = -ENOSYS;
    switch (nr) {
#if defined(__NR_openat)
        case __NR_openat:
            ret = handle_raw_openat((int) a0, (const char *) a1, (int) a2, (mode_t) a3);
            break;
#endif
#if defined(__NR_faccessat)
        case __NR_faccessat:
            ret = handle_raw_faccessat((int) a0, (const char *) a1, (int) a2, (int) a3);
            break;
#endif
#if defined(__NR_newfstatat)
        case __NR_newfstatat:
            ret = handle_raw_fstatat((int) a0, (const char *) a1, (void *) a2, (int) a3);
            break;
#endif
#if defined(__NR_fstatat64)
        case __NR_fstatat64:
            ret = handle_raw_fstatat((int) a0, (const char *) a1, (void *) a2, (int) a3);
            break;
#endif
#if defined(__NR_mkdirat)
        case __NR_mkdirat:
            ret = handle_raw_mkdirat((int) a0, (const char *) a1, (mode_t) a2);
            break;
#endif
#if defined(__NR_unlinkat)
        case __NR_unlinkat:
            ret = handle_raw_unlinkat((int) a0, (const char *) a1, (int) a2);
            break;
#endif
#if defined(__NR_renameat)
        case __NR_renameat:
            ret = handle_raw_renameat2((int) a0, (const char *) a1, (int) a2, (const char *) a3, 0);
            break;
#endif
#if defined(__NR_renameat2)
        case __NR_renameat2:
            ret = handle_raw_renameat2((int) a0, (const char *) a1, (int) a2, (const char *) a3, (unsigned int) a4);
            break;
#endif
#if defined(__NR_fchmodat)
        case __NR_fchmodat:
            ret = handle_raw_fchmodat((int) a0, (const char *) a1, (mode_t) a2, (int) a3);
            break;
#endif
#if defined(__NR_readlinkat)
        case __NR_readlinkat:
            ret = handle_raw_readlinkat((int) a0, (const char *) a1, (char *) a2, (size_t) a3);
            break;
#endif
#if defined(__NR_inotify_add_watch)
        case __NR_inotify_add_watch:
            ret = handle_raw_inotify_add_watch((int) a0, (const char *) a1, (uint32_t) a2);
            break;
#endif
        default:
            ret = raw_syscall6(nr, a0, a1, a2, a3, a4, a5);
            break;
    }

#if defined(__aarch64__)
    uc->uc_mcontext.regs[0] = (uint64_t) ret;
#elif defined(__arm__)
    uc->uc_mcontext.arm_r0 = (unsigned long) ret;
#endif
}

static bool find_libc_exec_range(uintptr_t *out_start, uintptr_t *out_end) {
    FILE *fp = orig_fopen ? orig_fopen("/proc/self/maps", "r") : fopen("/proc/self/maps", "r");
    if (!fp) return false;
    uintptr_t min_start = UINTPTR_MAX;
    uintptr_t max_end = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "/libc.so") != nullptr && strstr(line, "r-xp") != nullptr) {
            uintptr_t start = 0, end = 0;
            if (sscanf(line, "%lx-%lx", (unsigned long *) &start, (unsigned long *) &end) == 2) {
                if (start < min_start) min_start = start;
                if (end > max_end) max_end = end;
            }
        }
    }
    fclose(fp);
    if (min_start < max_end) {
        *out_start = min_start;
        *out_end = max_end;
        return true;
    }
    return false;
}

static void install_seccomp_filter() {
#if defined(__aarch64__) || defined(__arm__)
    uintptr_t libc_start = 0, libc_end = 0;
    if (!find_libc_exec_range(&libc_start, &libc_end)) {
        ALOGE("FileSystemHook: Could not locate libc.so r-xp range for Seccomp whitelist");
        return;
    }

    uintptr_t raw_start = (uintptr_t) &raw_syscall6;
    uintptr_t raw_end = (uintptr_t) &raw_syscall6_end;
#if defined(__arm__)
    raw_start &= ~(uintptr_t) 1;
    raw_end &= ~(uintptr_t) 1;
#endif
    if (raw_end <= raw_start) {
        raw_end = raw_start + 64;
    }

    struct sigaction sa{};
    sa.sa_sigaction = seccomp_sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, nullptr) != 0) {
        ALOGE("FileSystemHook: sigaction(SIGSYS) failed: %d", errno);
        return;
    }

    struct sock_filter filter[64];
    int n = 0;

    // 1. Load syscall number
    filter[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t) offsetof(struct seccomp_data, nr));

    // Collect target syscalls to trap
    uint32_t targets[] = {
#if defined(__NR_openat)
        __NR_openat,
#endif
#if defined(__NR_faccessat)
        __NR_faccessat,
#endif
#if defined(__NR_newfstatat)
        __NR_newfstatat,
#endif
#if defined(__NR_fstatat64)
        __NR_fstatat64,
#endif
#if defined(__NR_mkdirat)
        __NR_mkdirat,
#endif
#if defined(__NR_unlinkat)
        __NR_unlinkat,
#endif
#if defined(__NR_renameat)
        __NR_renameat,
#endif
#if defined(__NR_renameat2)
        __NR_renameat2,
#endif
#if defined(__NR_fchmodat)
        __NR_fchmodat,
#endif
#if defined(__NR_readlinkat)
        __NR_readlinkat,
#endif
#if defined(__NR_inotify_add_watch)
        __NR_inotify_add_watch,
#endif
    };
    const int num_targets = (int) (sizeof(targets) / sizeof(targets[0]));
    for (int i = 0; i < num_targets; ++i) {
        uint8_t jt = (uint8_t) (num_targets - i);
        filter[n++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, targets[i], jt, 0);
    }
    // Non-target syscall -> ALLOW immediately
    filter[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

#if defined(__aarch64__)
    uint32_t raw_hi = (uint32_t) (raw_start >> 32);
    uint32_t raw_lo_start = (uint32_t) (raw_start & 0xffffffffULL);
    uint32_t raw_lo_end = (uint32_t) (raw_end & 0xffffffffULL);

    uint32_t libc_hi = (uint32_t) (libc_start >> 32);
    uint32_t libc_lo_start = (uint32_t) (libc_start & 0xffffffffULL);
    uint32_t libc_lo_end = (uint32_t) (libc_end & 0xffffffffULL);

    // 2. Check if PC is inside [raw_syscall6, raw_syscall6_end) -> ALLOW
    filter[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t) offsetof(struct seccomp_data, instruction_pointer) + 4);
    filter[n++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, raw_hi, 0, 4);
    filter[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t) offsetof(struct seccomp_data, instruction_pointer));
    filter[n++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, raw_lo_start, 0, 2);
    filter[n++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, raw_lo_end, 1, 0);
    filter[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    // 3. Check if PC is inside [libc_start, libc_end) -> ALLOW
    filter[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t) offsetof(struct seccomp_data, instruction_pointer) + 4);
    filter[n++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, libc_hi, 0, 4);
    filter[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t) offsetof(struct seccomp_data, instruction_pointer));
    filter[n++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, libc_lo_start, 0, 2);
    filter[n++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, libc_lo_end, 1, 0);
    filter[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    // 4. Direct inline svc #0 outside libc.so and outside raw_syscall6 (e.g. libthemis.so) -> TRAP
    filter[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP);
#elif defined(__arm__)
    // 2. Check if PC is inside [raw_start, raw_end) -> ALLOW
    filter[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t) offsetof(struct seccomp_data, instruction_pointer));
    filter[n++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t) raw_start, 0, 2);
    filter[n++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t) raw_end, 1, 0);
    filter[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    // 3. Check if PC is inside [libc_start, libc_end) -> ALLOW
    filter[n++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t) libc_start, 0, 2);
    filter[n++] = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t) libc_end, 1, 0);
    filter[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    // 4. Direct inline svc #0 outside libc.so -> TRAP
    filter[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP);
#endif

    struct sock_fprog prog{};
    prog.len = (unsigned short) n;
    prog.filter = filter;

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == 0) {
        ALOGD("FileSystemHook: Installed Seccomp-BPF filter (raw_syscall6=%p..%p, libc=%p..%p)",
              (void *) raw_start, (void *) raw_end, (void *) libc_start, (void *) libc_end);
    } else {
        ALOGE("FileSystemHook: Failed to install Seccomp-BPF filter: %d", errno);
    }
#endif
}

static uintptr_t g_hooked_addrs[64];
static size_t g_hooked_count = 0;

static bool is_already_hooked(uintptr_t addr) {
    for (size_t i = 0; i < g_hooked_count; ++i) {
        uintptr_t diff = (addr > g_hooked_addrs[i]) ? (addr - g_hooked_addrs[i]) : (g_hooked_addrs[i] - addr);
        if (diff < 16) {
            return true;
        }
    }
    return false;
}

static void ensure_readable_code(void *addr) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    uintptr_t start = (uintptr_t) addr & ~((uintptr_t) page_size - 1);
    mprotect((void *) start, (size_t) page_size * 2, PROT_READ | PROT_EXEC);
}

static void hook_libc_symbol(void *handle, const char *name, void *replace_func, void **orig_func) {
    void *addr = xdl_sym(handle, name, nullptr);
    if (!addr) {
        return;
    }
    uintptr_t uaddr = (uintptr_t) addr;
    if (is_already_hooked(uaddr)) {
        return;
    }
    ensure_readable_code(addr);
#if defined(__aarch64__)
    const uint32_t *insns = (const uint32_t *) addr;
    for (int i = 0; i < 6; ++i) {
        uint32_t insn = insns[i];
        if ((insn & 0x7c000000) == 0x14000000) {
            int32_t imm26 = ((int32_t) (insn << 6)) >> 4;
            uintptr_t target = (uintptr_t) (&insns[i]) + (intptr_t) imm26;
            if (is_already_hooked(target)) {
                ALOGD("FileSystemHook: %s already delegates to hooked target %p, skipping wrapper hook", name, (void *) target);
                return;
            }
            if (i < 3 && (insn & 0xfc000000) == 0x14000000) {
                ALOGD("FileSystemHook: %s has short unconditional branch at insn %d, skipping", name, i);
                return;
            }
        }
        if (i < 3 && insn == 0xd65f03c0) {
            ALOGD("FileSystemHook: %s has short ret at insn %d, skipping", name, i);
            return;
        }
    }
#endif
    if (DobbyHook(addr, replace_func, orig_func) == RS_SUCCESS) {
        if (g_hooked_count < 64) {
            g_hooked_addrs[g_hooked_count++] = uaddr;
        }
        ALOGD("FileSystemHook: Hooked %s at %p", name, addr);
    } else {
        ALOGE("FileSystemHook: Failed to hook %s at %p", name, addr);
    }
}

void FileSystemHook::init() {
    g_self_pid = getpid();
    if (!g_anti_cheat_bypass_enabled || g_is_excluded_app) {
        ALOGD("FileSystemHook: Skipped (enabled=%d, excluded=%d, pkg=%s)",
              g_anti_cheat_bypass_enabled ? 1 : 0, g_is_excluded_app ? 1 : 0, g_current_package);
        return;
    }

    ALOGD("FileSystemHook: Initializing file system & anti-GG-detection hooks for %s", g_current_package);

    void *handle = xdl_open("libc.so", XDL_DEFAULT);
    if (!handle) {
        ALOGE("FileSystemHook: Failed to open libc.so");
        return;
    }

    // Hook *at syscall/core functions first
    hook_libc_symbol(handle, "mkdirat", (void *) new_mkdirat, (void **) &orig_mkdirat);
    hook_libc_symbol(handle, "openat", (void *) new_openat, (void **) &orig_openat);
    hook_libc_symbol(handle, "openat64", (void *) new_openat64, (void **) &orig_openat64);
    hook_libc_symbol(handle, "__openat_2", (void *) new___openat_2, (void **) &orig___openat_2);
    hook_libc_symbol(handle, "faccessat", (void *) new_faccessat, (void **) &orig_faccessat);
    hook_libc_symbol(handle, "fstatat", (void *) new_fstatat, (void **) &orig_fstatat);
    hook_libc_symbol(handle, "fstatat64", (void *) new_fstatat64, (void **) &orig_fstatat64);
    hook_libc_symbol(handle, "unlinkat", (void *) new_unlinkat, (void **) &orig_unlinkat);
    hook_libc_symbol(handle, "renameat", (void *) new_renameat, (void **) &orig_renameat);
    hook_libc_symbol(handle, "renameat2", (void *) new_renameat2, (void **) &orig_renameat2);
    hook_libc_symbol(handle, "fchmodat", (void *) new_fchmodat, (void **) &orig_fchmodat);
    hook_libc_symbol(handle, "readlinkat", (void *) new_readlinkat, (void **) &orig_readlinkat);
    hook_libc_symbol(handle, "inotify_add_watch", (void *) new_inotify_add_watch, (void **) &orig_inotify_add_watch);

    // Hook non-*at functions
    hook_libc_symbol(handle, "mkdir", (void *) new_mkdir, (void **) &orig_mkdir);
    hook_libc_symbol(handle, "open", (void *) new_open, (void **) &orig_open);
    hook_libc_symbol(handle, "open64", (void *) new_open64, (void **) &orig_open64);
    hook_libc_symbol(handle, "__open_2", (void *) new___open_2, (void **) &orig___open_2);
    hook_libc_symbol(handle, "fopen", (void *) new_fopen, (void **) &orig_fopen);
    hook_libc_symbol(handle, "opendir", (void *) new_opendir, (void **) &orig_opendir);
    hook_libc_symbol(handle, "access", (void *) new_access, (void **) &orig_access);
    hook_libc_symbol(handle, "stat", (void *) new_stat, (void **) &orig_stat);
    hook_libc_symbol(handle, "lstat", (void *) new_lstat, (void **) &orig_lstat);
    hook_libc_symbol(handle, "unlink", (void *) new_unlink, (void **) &orig_unlink);
    hook_libc_symbol(handle, "rmdir", (void *) new_rmdir, (void **) &orig_rmdir);
    hook_libc_symbol(handle, "rename", (void *) new_rename, (void **) &orig_rename);
    hook_libc_symbol(handle, "chmod", (void *) new_chmod, (void **) &orig_chmod);
    hook_libc_symbol(handle, "readlink", (void *) new_readlink, (void **) &orig_readlink);

    xdl_close(handle);

    // Install Seccomp-BPF filter to intercept all 229 direct inline svc #0 calls in libthemis.so / libtersafe2.so
    install_seccomp_filter();
}
