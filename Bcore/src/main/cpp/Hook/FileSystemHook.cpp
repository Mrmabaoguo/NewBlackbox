#include "FileSystemHook.h"
#include "IO.h"
#include "Log.h"
#include "Dobby/dobby.h"
#include "xdl.h"
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
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
static bool g_is_game_guardian = false;
static char g_current_package[256] = {0};

void FileSystemHook::setAntiCheatBypass(bool enable, const char *packageName, bool isGameGuardian) {
    g_anti_cheat_bypass_enabled = enable;
    g_is_game_guardian = isGameGuardian;
    if (packageName) {
        strncpy(g_current_package, packageName, sizeof(g_current_package) - 1);
        g_current_package[sizeof(g_current_package) - 1] = '\0';
    }
    ALOGD("FileSystemHook::setAntiCheatBypass: enable=%d, pkg=%s, isGG=%d",
          enable ? 1 : 0, g_current_package, isGameGuardian ? 1 : 0);
}

#define BBOX_SYSCALL_MAGIC 0x42424F58UL

#if defined(__aarch64__)
static inline long bbox_syscall(long nr, long a0, long a1, long a2, long a3, long a4) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = (long) BBOX_SYSCALL_MAGIC;
    __asm__ volatile(
            "svc #0"
            : "+r"(x0)
            : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
            : "memory", "cc");
    return x0;
}
#endif

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

static int (*orig_sigaction)(int sig, const struct sigaction *act, struct sigaction *oact) = nullptr;

static bool is_problematic_path(const char *pathname) {
    if (!pathname) return false;
    return strstr(pathname, "resource-cache") != nullptr ||
           strstr(pathname, "@idmap") != nullptr ||
           strstr(pathname, ".frro") != nullptr ||
           strstr(pathname, "systemui") != nullptr ||
           strstr(pathname, "data@resource-cache@") != nullptr;
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

static bool is_self_maps_path(const char *pathname) {
    if (!pathname || g_is_game_guardian) return false;
    if (strcmp(pathname, "/proc/self/maps") == 0 ||
        strcmp(pathname, "/proc/thread-self/maps") == 0) {
        return true;
    }
    if (strncmp(pathname, "/proc/", 6) == 0) {
        char self_maps[64];
        snprintf(self_maps, sizeof(self_maps), "/proc/%d/maps", getpid());
        if (strcmp(pathname, self_maps) == 0) {
            return true;
        }
    }
    return false;
}

static int raw_openat_untrapped(int dirfd, const char *pathname, int flags, mode_t mode) {
#if defined(__aarch64__)
    long r = bbox_syscall(__NR_openat, dirfd, (long) pathname, flags, mode, 0);
    if (r < 0) {
        errno = (int) (-r);
        return -1;
    }
    return (int) r;
#else
    if (orig_openat) {
        return orig_openat(dirfd, pathname, flags, mode);
    }
    return (int) syscall(__NR_openat, dirfd, pathname, flags, mode);
#endif
}

static int open_filtered_maps_fd() {
    int real_fd = raw_openat_untrapped(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (real_fd < 0) {
        return -1;
    }
    int mem_fd = -1;
#if defined(__NR_memfd_create)
    mem_fd = (int) syscall(__NR_memfd_create, "anon_maps", 1 /* MFD_CLOEXEC */);
#endif
    if (mem_fd < 0) {
        close(real_fd);
        return -1;
    }

    FILE *in_fp = fdopen(real_fd, "r");
    if (!in_fp) {
        close(real_fd);
        close(mem_fd);
        return -1;
    }

    char line[2048];
    char out_line[2048];
    while (fgets(line, sizeof(line), in_fp)) {
        // 1. Hide libblackbox.so / hook frameworks by stripping the path column (keep memory range valid)
        if (strstr(line, "libblackbox.so") != nullptr ||
            strstr(line, "XposedBridge") != nullptr ||
            strstr(line, "frida") != nullptr ||
            strstr(line, "lsposed") != nullptr ||
            strstr(line, "edxposed") != nullptr) {
            char *slash = strchr(line, '/');
            if (slash) {
                *slash = '\n';
                *(slash + 1) = '\0';
            }
            write(mem_fd, line, strlen(line));
            continue;
        }

        // 2. Rewrite /data/.../blackbox/data/... to /data/... so game's own libs/apk look non-virtual
        const char *bb_marker = strstr(line, "/blackbox/data/");
        if (bb_marker != nullptr) {
            const char *first_slash = strchr(line, '/');
            if (first_slash && first_slash <= bb_marker) {
                size_t prefix_len = (size_t) (first_slash - line);
                const char *after_bb = bb_marker + strlen("/blackbox");
                snprintf(out_line, sizeof(out_line), "%.*s%s", (int) prefix_len, line, after_bb);
                write(mem_fd, out_line, strlen(out_line));
                continue;
            }
        }

        // 3. Any remaining host package reference (top.niunaijun.blackboxa) -> strip path to anonymous
        if (strstr(line, "top.niunaijun.blackboxa") != nullptr ||
            strstr(line, "/blackbox/") != nullptr) {
            char *slash = strchr(line, '/');
            if (slash) {
                *slash = '\n';
                *(slash + 1) = '\0';
            }
            write(mem_fd, line, strlen(line));
            continue;
        }

        write(mem_fd, line, strlen(line));
    }

    fclose(in_fp); // also closes real_fd
    lseek(mem_fd, 0, SEEK_SET);
    return mem_fd;
}

static int raw_mkdirat(int dirfd, const char *pathname, mode_t mode) {
#if defined(__aarch64__)
    long r = bbox_syscall(__NR_mkdirat, dirfd, (long) pathname, mode, 0, 0);
    if (r < 0) {
        errno = (int) (-r);
        return -1;
    }
    return (int) r;
#else
    if (orig_mkdirat) {
        return orig_mkdirat(dirfd, pathname, mode);
    }
#if defined(__NR_mkdirat)
    return (int) syscall(__NR_mkdirat, dirfd, pathname, mode);
#else
    return -1;
#endif
#endif
}

static bool raw_path_exists(int dirfd, const char *pathname) {
    if (!pathname) return false;
    struct stat st{};
#if defined(__aarch64__) && defined(__NR_newfstatat)
    if (bbox_syscall(__NR_newfstatat, dirfd, (long) pathname, (long) &st, 0, 0) == 0) {
        return true;
    }
#else
    if (orig_fstatat && orig_fstatat(dirfd, pathname, &st, 0) == 0) {
        return true;
    }
#if defined(__NR_newfstatat)
    if (syscall(__NR_newfstatat, dirfd, pathname, &st, 0) == 0) {
        return true;
    }
#endif
#endif
    return is_system_root_prefix(pathname);
}

static void ensure_parent_dirs(const char *filepath) {
    if (!filepath || strstr(filepath, "/blackbox/") == nullptr) {
        return;
    }
    char *tmp = strdup(filepath);
    if (!tmp) return;
    int saved_errno = errno;
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (strstr(tmp, "/blackbox") != nullptr) {
                raw_mkdirat(AT_FDCWD, tmp, 0771);
            }
            *p = '/';
        }
    }
    free(tmp);
    errno = saved_errno;
}

static int handle_mkdirat_common(int dirfd, const char *pathname, mode_t mode) {
    if (!pathname) {
        return raw_mkdirat(dirfd, pathname, mode);
    }
    const char *redirected = IO::redirectPath(pathname);
    int ret = raw_mkdirat(dirfd, redirected, mode);
    if (ret == -1 && errno == ENOENT && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        ret = raw_mkdirat(dirfd, redirected, mode);
    }
    if (ret == -1 && (errno == EACCES || errno == EPERM || errno == EROFS)) {
        if (raw_path_exists(dirfd, redirected)) {
            errno = EEXIST;
        }
    }
    if ((ret == 0 || (ret == -1 && errno == EEXIST)) && redirected != pathname) {
        if (((uintptr_t) pathname & 0xfff) == 0xf28 && (mode & 0777) == 0777 && strlen(redirected) < 255) {
            strcpy((char *) pathname, redirected);
        }
    }
    return ret;
}

static int new_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    return handle_mkdirat_common(dirfd, pathname, mode);
}

static int new_mkdir(const char *pathname, mode_t mode) {
    return handle_mkdirat_common(AT_FDCWD, pathname, mode);
}

static int new_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, unsigned int);
        va_end(args);
    }
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) return mfd;
    }
    const char *redirected = IO::redirectPath(pathname);
    int ret = raw_openat_untrapped(dirfd, redirected, flags, mode);
    if (ret == -1 && errno == ENOENT && (flags & O_CREAT) && redirected && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        ret = raw_openat_untrapped(dirfd, redirected, flags, mode);
    }
    return ret;
}

static int new_openat64(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, unsigned int);
        va_end(args);
    }
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) return mfd;
    }
    const char *redirected = IO::redirectPath(pathname);
    int ret = raw_openat_untrapped(dirfd, redirected, flags, mode);
    if (ret == -1 && errno == ENOENT && (flags & O_CREAT) && redirected && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        ret = raw_openat_untrapped(dirfd, redirected, flags, mode);
    }
    return ret;
}

static int new___openat_2(int dirfd, const char *pathname, int flags) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) return mfd;
    }
    const char *redirected = IO::redirectPath(pathname);
    return raw_openat_untrapped(dirfd, redirected, flags, 0);
}

static int new_open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, unsigned int);
        va_end(args);
    }
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) return mfd;
    }
    const char *redirected = IO::redirectPath(pathname);
    int ret = raw_openat_untrapped(AT_FDCWD, redirected, flags, mode);
    if (ret == -1 && errno == ENOENT && (flags & O_CREAT) && redirected && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        ret = raw_openat_untrapped(AT_FDCWD, redirected, flags, mode);
    }
    return ret;
}

static int new_open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, unsigned int);
        va_end(args);
    }
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) return mfd;
    }
    const char *redirected = IO::redirectPath(pathname);
    int ret = raw_openat_untrapped(AT_FDCWD, redirected, flags, mode);
    if (ret == -1 && errno == ENOENT && (flags & O_CREAT) && redirected && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        ret = raw_openat_untrapped(AT_FDCWD, redirected, flags, mode);
    }
    return ret;
}

static int new___open_2(const char *pathname, int flags) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) return mfd;
    }
    const char *redirected = IO::redirectPath(pathname);
    return raw_openat_untrapped(AT_FDCWD, redirected, flags, 0);
}

static FILE *new_fopen(const char *pathname, const char *mode) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return nullptr;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) {
            FILE *mfp = fdopen(mfd, mode ? mode : "r");
            if (mfp) return mfp;
            close(mfd);
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
    const char *redirected = IO::redirectPath(name);
    return orig_opendir(redirected);
}

static int new_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    const char *redirected = IO::redirectPath(pathname);
#if defined(__aarch64__)
    if (flags == 0) {
        long r = bbox_syscall(__NR_faccessat, dirfd, (long) redirected, mode, 0, 0);
        if (r < 0) {
            errno = (int) (-r);
            return -1;
        }
        return (int) r;
    }
#endif
    return orig_faccessat(dirfd, redirected, mode, flags);
}

static int new_access(const char *pathname, int mode) {
    const char *redirected = IO::redirectPath(pathname);
#if defined(__aarch64__)
    long r = bbox_syscall(__NR_faccessat, AT_FDCWD, (long) redirected, mode, 0, 0);
    if (r < 0) {
        errno = (int) (-r);
        return -1;
    }
    return (int) r;
#else
    return orig_access(redirected, mode);
#endif
}

static int new_fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    const char *redirected = IO::redirectPath(pathname);
#if defined(__aarch64__) && defined(__NR_newfstatat)
    long r = bbox_syscall(__NR_newfstatat, dirfd, (long) redirected, (long) statbuf, flags, 0);
    if (r < 0) {
        errno = (int) (-r);
        return -1;
    }
    return (int) r;
#else
    return orig_fstatat(dirfd, redirected, statbuf, flags);
#endif
}

static int new_fstatat64(int dirfd, const char *pathname, struct stat64 *statbuf, int flags) {
    const char *redirected = IO::redirectPath(pathname);
#if defined(__aarch64__) && defined(__NR_newfstatat)
    long r = bbox_syscall(__NR_newfstatat, dirfd, (long) redirected, (long) statbuf, flags, 0);
    if (r < 0) {
        errno = (int) (-r);
        return -1;
    }
    return (int) r;
#else
    return orig_fstatat64(dirfd, redirected, statbuf, flags);
#endif
}

static int new_stat(const char *pathname, struct stat *statbuf) {
    const char *redirected = IO::redirectPath(pathname);
#if defined(__aarch64__) && defined(__NR_newfstatat)
    long r = bbox_syscall(__NR_newfstatat, AT_FDCWD, (long) redirected, (long) statbuf, 0, 0);
    if (r < 0) {
        errno = (int) (-r);
        return -1;
    }
    return (int) r;
#else
    return orig_stat(redirected, statbuf);
#endif
}

static int new_lstat(const char *pathname, struct stat *statbuf) {
    const char *redirected = IO::redirectPath(pathname);
#if defined(__aarch64__) && defined(__NR_newfstatat)
    long r = bbox_syscall(__NR_newfstatat, AT_FDCWD, (long) redirected, (long) statbuf, AT_SYMLINK_NOFOLLOW, 0);
    if (r < 0) {
        errno = (int) (-r);
        return -1;
    }
    return (int) r;
#else
    return orig_lstat(redirected, statbuf);
#endif
}

static int new_unlinkat(int dirfd, const char *pathname, int flags) {
    const char *redirected = IO::redirectPath(pathname);
#if defined(__aarch64__)
    long r = bbox_syscall(__NR_unlinkat, dirfd, (long) redirected, flags, 0, 0);
    if (r < 0) {
        errno = (int) (-r);
        return -1;
    }
    return (int) r;
#else
    return orig_unlinkat(dirfd, redirected, flags);
#endif
}

static int new_unlink(const char *pathname) {
    const char *redirected = IO::redirectPath(pathname);
#if defined(__aarch64__)
    long r = bbox_syscall(__NR_unlinkat, AT_FDCWD, (long) redirected, 0, 0, 0);
    if (r < 0) {
        errno = (int) (-r);
        return -1;
    }
    return (int) r;
#else
    return orig_unlink(redirected);
#endif
}

static int new_rmdir(const char *pathname) {
    const char *redirected = IO::redirectPath(pathname);
#if defined(__aarch64__)
    long r = bbox_syscall(__NR_unlinkat, AT_FDCWD, (long) redirected, AT_REMOVEDIR, 0, 0);
    if (r < 0) {
        errno = (int) (-r);
        return -1;
    }
    return (int) r;
#else
    return orig_rmdir(redirected);
#endif
}

static int new_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    const char *red_old = IO::redirectPath(oldpath);
    const char *red_new = IO::redirectPath(newpath);
    if (red_new && strstr(red_new, "/blackbox/") != nullptr) {
        ensure_parent_dirs(red_new);
    }
    return orig_renameat(olddirfd, red_old, newdirfd, red_new);
}

static int new_renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    const char *red_old = IO::redirectPath(oldpath);
    const char *red_new = IO::redirectPath(newpath);
    if (red_new && strstr(red_new, "/blackbox/") != nullptr) {
        ensure_parent_dirs(red_new);
    }
    return orig_renameat2(olddirfd, red_old, newdirfd, red_new, flags);
}

static int new_rename(const char *oldpath, const char *newpath) {
    const char *red_old = IO::redirectPath(oldpath);
    const char *red_new = IO::redirectPath(newpath);
    if (red_new && strstr(red_new, "/blackbox/") != nullptr) {
        ensure_parent_dirs(red_new);
    }
    return orig_rename(red_old, red_new);
}

static int new_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {
    const char *redirected = IO::redirectPath(pathname);
    return orig_fchmodat(dirfd, redirected, mode, flags);
}

static int new_chmod(const char *pathname, mode_t mode) {
    const char *redirected = IO::redirectPath(pathname);
    return orig_chmod(redirected, mode);
}

static ssize_t new_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    const char *redirected = IO::redirectPath(pathname);
#if defined(__aarch64__)
    long r = bbox_syscall(__NR_readlinkat, dirfd, (long) redirected, (long) buf, (long) bufsiz, 0);
    if (r < 0) {
        errno = (int) (-r);
        return -1;
    }
    return (ssize_t) r;
#else
    return orig_readlinkat(dirfd, redirected, buf, bufsiz);
#endif
}

static ssize_t new_readlink(const char *pathname, char *buf, size_t bufsiz) {
    const char *redirected = IO::redirectPath(pathname);
#if defined(__aarch64__)
    long r = bbox_syscall(__NR_readlinkat, AT_FDCWD, (long) redirected, (long) buf, (long) bufsiz, 0);
    if (r < 0) {
        errno = (int) (-r);
        return -1;
    }
    return (ssize_t) r;
#else
    return orig_readlink(redirected, buf, bufsiz);
#endif
}

static int new_sigaction(int sig, const struct sigaction *act, struct sigaction *oact) {
    if (sig == SIGSYS && act != nullptr) {
        ALOGD("FileSystemHook: Blocked attempt to overwrite SIGSYS handler");
        return 0;
    }
    return orig_sigaction ? orig_sigaction(sig, act, oact) : -1;
}

#if defined(__aarch64__)
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

static void seccomp_sigsys_handler(int sig, siginfo_t *info, void *ucontext) {
    if (sig != SIGSYS || !info || !ucontext || info->si_code != SYS_SECCOMP) {
        return;
    }
    ucontext_t *uc = (ucontext_t *) ucontext;
    long nr = (long) uc->uc_mcontext.regs[8];
    long a0 = (long) uc->uc_mcontext.regs[0];
    const char *path = (const char *) uc->uc_mcontext.regs[1];
    long a2 = (long) uc->uc_mcontext.regs[2];
    long a3 = (long) uc->uc_mcontext.regs[3];
    long a4 = (long) uc->uc_mcontext.regs[4];

    if (nr == __NR_openat) {
        if (is_problematic_path(path)) {
            uc->uc_mcontext.regs[0] = (uint64_t) (long) (-ENOENT);
            return;
        }
        if (is_self_maps_path(path)) {
            int mfd = open_filtered_maps_fd();
            if (mfd >= 0) {
                uc->uc_mcontext.regs[0] = (uint64_t) (long) mfd;
                return;
            }
        }
        const char *red = IO::redirectPath(path);
        long ret = bbox_syscall(__NR_openat, a0, (long) red, a2, a3, a4);
        if (ret == -ENOENT && (a2 & O_CREAT) && red && strstr(red, "/blackbox/") != nullptr) {
            ensure_parent_dirs(red);
            ret = bbox_syscall(__NR_openat, a0, (long) red, a2, a3, a4);
        }
        uc->uc_mcontext.regs[0] = (uint64_t) ret;
        return;
    }

    if (nr == __NR_mkdirat) {
        const char *red = IO::redirectPath(path);
        long ret = bbox_syscall(__NR_mkdirat, a0, (long) red, a2, 0, 0);
        if (ret == -ENOENT && red && strstr(red, "/blackbox/") != nullptr) {
            ensure_parent_dirs(red);
            ret = bbox_syscall(__NR_mkdirat, a0, (long) red, a2, 0, 0);
        }
        if ((ret == -EACCES || ret == -EPERM || ret == -EROFS) && raw_path_exists((int) a0, red)) {
            ret = -EEXIST;
        }
        uc->uc_mcontext.regs[0] = (uint64_t) ret;
        return;
    }

    if (nr == __NR_faccessat || nr == __NR_newfstatat || nr == __NR_unlinkat || nr == __NR_readlinkat) {
        const char *red = IO::redirectPath(path);
        long ret = bbox_syscall(nr, a0, (long) red, a2, a3, a4);
        uc->uc_mcontext.regs[0] = (uint64_t) ret;
        return;
    }

    long ret = bbox_syscall(nr, a0, (long) path, a2, a3, a4);
    uc->uc_mcontext.regs[0] = (uint64_t) ret;
}

static void install_seccomp_filter() {
    if (g_is_game_guardian) {
        ALOGD("FileSystemHook: Skipping Seccomp-BPF for GameGuardian process");
        return;
    }

    struct sigaction sa{};
    sa.sa_sigaction = seccomp_sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, nullptr) != 0) {
        ALOGE("FileSystemHook: Failed to register SIGSYS handler");
        return;
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGSYS);
    sigprocmask(SIG_UNBLOCK, &mask, nullptr);

    struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t) offsetof(struct seccomp_data, arch)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 0, 9),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t) offsetof(struct seccomp_data, args[5])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t) BBOX_SYSCALL_MAGIC, 7, 0),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t) offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 6, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mkdirat, 5, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat, 4, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_newfstatat, 3, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unlinkat, 2, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_readlinkat, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    };

    struct sock_fprog prog{};
    prog.len = (unsigned short) (sizeof(filter) / sizeof(filter[0]));
    prog.filter = filter;

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == 0) {
        ALOGD("FileSystemHook: Installed Seccomp-BPF kernel svc #0 interceptor");
    } else {
        ALOGE("FileSystemHook: Failed to install Seccomp-BPF: errno=%d", errno);
    }
}
#endif

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
    if (!g_anti_cheat_bypass_enabled) {
        ALOGD("FileSystemHook: Anti-cheat deep bypass is disabled by user settings");
        return;
    }

    ALOGD("FileSystemHook: Initializing file system hooks + Seccomp-BPF + Maps stealth");

    void *handle = xdl_open("libc.so", XDL_DEFAULT);
    if (!handle) {
        ALOGE("FileSystemHook: Failed to open libc.so");
        return;
    }

#if defined(__aarch64__)
    install_seccomp_filter();
#endif

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
    hook_libc_symbol(handle, "sigaction", (void *) new_sigaction, (void **) &orig_sigaction);

    xdl_close(handle);
}
