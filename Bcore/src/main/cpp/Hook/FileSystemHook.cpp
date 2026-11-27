#include "FileSystemHook.h"
#include "IO.h"
#include "Log.h"
#include "Dobby/dobby.h"
#include "xdl.h"
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/inotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <stdarg.h>
#include <cstring>
#include <cstdlib>
#include <errno.h>

static bool g_anti_cheat_bypass_enabled = true;
static bool g_is_excluded_app = false;
static char g_current_package[256] = {0};

void FileSystemHook::setAntiCheatBypass(bool enable, const char *packageName, bool isGameGuardian) {
    g_anti_cheat_bypass_enabled = enable && !isGameGuardian;
    g_is_excluded_app = isGameGuardian;
    if (packageName) {
        strncpy(g_current_package, packageName, sizeof(g_current_package) - 1);
        g_current_package[sizeof(g_current_package) - 1] = '\0';
    }
    ALOGD("FileSystemHook::setAntiCheatBypass: enable=%d, pkg=%s, excluded=%d",
          g_anti_cheat_bypass_enabled ? 1 : 0, g_current_package, isGameGuardian ? 1 : 0);
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

static bool is_problematic_path(const char *pathname) {
    if (!pathname) return false;
    // Block the game's anti-cheat from scanning /proc/<other_pid>/... (such as GG or GG's lib5.so daemon sharing the same UID)
    if (!g_is_excluded_app && strncmp(pathname, "/proc/", 6) == 0) {
        char c = pathname[6];
        if (c >= '1' && c <= '9') {
            int target_pid = atoi(pathname + 6);
            if (target_pid > 0 && target_pid != getpid()) {
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

static bool is_proc_status_path(const char *pathname) {
    if (!pathname || g_is_excluded_app) return false;
    if (strncmp(pathname, "/proc/", 6) != 0) return false;
    size_t len = strlen(pathname);
    return (len >= 7 && strcmp(pathname + len - 7, "/status") == 0);
}

static bool is_self_maps_path(const char *pathname) {
    if (!pathname || g_is_excluded_app) return false;
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

static int open_filtered_status_fd(const char *status_path) {
    if (!orig_openat) return -1;
    int real_fd = orig_openat(AT_FDCWD, status_path, O_RDONLY | O_CLOEXEC, 0);
    if (real_fd < 0) return -1;

    int mem_fd = -1;
#if defined(__NR_memfd_create)
    mem_fd = (int) syscall(__NR_memfd_create, "anon_status", 1 /* MFD_CLOEXEC */);
#endif
    if (mem_fd < 0) {
        close(real_fd);
        return -1;
    }

    char buf[4096];
    ssize_t n = read(real_fd, buf, sizeof(buf) - 1);
    close(real_fd);
    if (n <= 0) {
        close(mem_fd);
        return -1;
    }
    buf[n] = '\0';

    char *saveptr = nullptr;
    char *line = strtok_r(buf, "\n", &saveptr);
    while (line) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            const char *clean = "TracerPid:\t0\n";
            write(mem_fd, clean, strlen(clean));
        } else if (strncmp(line, "State:", 6) == 0 && (strstr(line, "T (") || strstr(line, "t ("))) {
            const char *clean = "State:\tS (sleeping)\n";
            write(mem_fd, clean, strlen(clean));
        } else {
            write(mem_fd, line, strlen(line));
            write(mem_fd, "\n", 1);
        }
        line = strtok_r(nullptr, "\n", &saveptr);
    }

    lseek(mem_fd, 0, SEEK_SET);
    return mem_fd;
}

static int open_filtered_maps_fd() {
    if (!orig_openat) return -1;
    int real_fd = orig_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
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

    fclose(in_fp);
    lseek(mem_fd, 0, SEEK_SET);
    return mem_fd;
}

static int raw_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    if (orig_mkdirat) {
        return orig_mkdirat(dirfd, pathname, mode);
    }
#if defined(__NR_mkdirat)
    return (int) syscall(__NR_mkdirat, dirfd, pathname, mode);
#else
    return -1;
#endif
}

static bool raw_path_exists(int dirfd, const char *pathname) {
    if (!pathname) return false;
    struct stat st{};
    if (orig_fstatat) {
        if (orig_fstatat(dirfd, pathname, &st, 0) == 0) {
            return true;
        }
    }
#if defined(__NR_newfstatat)
    if (syscall(__NR_newfstatat, dirfd, pathname, &st, 0) == 0) {
        return true;
    }
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
    if (is_proc_status_path(pathname)) {
        int sfd = open_filtered_status_fd(pathname);
        if (sfd >= 0) return sfd;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) return mfd;
    }
    const char *redirected = IO::redirectPath(pathname);
    int ret = orig_openat(dirfd, redirected, flags, mode);
    if (ret == -1 && errno == ENOENT && (flags & O_CREAT) && redirected && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        ret = orig_openat(dirfd, redirected, flags, mode);
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
    if (is_proc_status_path(pathname)) {
        int sfd = open_filtered_status_fd(pathname);
        if (sfd >= 0) return sfd;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) return mfd;
    }
    const char *redirected = IO::redirectPath(pathname);
    int ret = orig_openat64(dirfd, redirected, flags, mode);
    if (ret == -1 && errno == ENOENT && (flags & O_CREAT) && redirected && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        ret = orig_openat64(dirfd, redirected, flags, mode);
    }
    return ret;
}

static int new___openat_2(int dirfd, const char *pathname, int flags) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    if (is_proc_status_path(pathname)) {
        int sfd = open_filtered_status_fd(pathname);
        if (sfd >= 0) return sfd;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) return mfd;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig___openat_2(dirfd, redirected, flags);
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
    if (is_proc_status_path(pathname)) {
        int sfd = open_filtered_status_fd(pathname);
        if (sfd >= 0) return sfd;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) return mfd;
    }
    const char *redirected = IO::redirectPath(pathname);
    int ret = orig_open(redirected, flags, mode);
    if (ret == -1 && errno == ENOENT && (flags & O_CREAT) && redirected && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        ret = orig_open(redirected, flags, mode);
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
    if (is_proc_status_path(pathname)) {
        int sfd = open_filtered_status_fd(pathname);
        if (sfd >= 0) return sfd;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) return mfd;
    }
    const char *redirected = IO::redirectPath(pathname);
    int ret = orig_open64(redirected, flags, mode);
    if (ret == -1 && errno == ENOENT && (flags & O_CREAT) && redirected && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        ret = orig_open64(redirected, flags, mode);
    }
    return ret;
}

static int new___open_2(const char *pathname, int flags) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    if (is_proc_status_path(pathname)) {
        int sfd = open_filtered_status_fd(pathname);
        if (sfd >= 0) return sfd;
    }
    if (is_self_maps_path(pathname)) {
        int mfd = open_filtered_maps_fd();
        if (mfd >= 0) return mfd;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig___open_2(redirected, flags);
}

static FILE *new_fopen(const char *pathname, const char *mode) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return nullptr;
    }
    if (is_proc_status_path(pathname)) {
        int sfd = open_filtered_status_fd(pathname);
        if (sfd >= 0) {
            FILE *sfp = fdopen(sfd, mode ? mode : "r");
            if (sfp) return sfp;
            close(sfd);
        }
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
    if (is_problematic_path(name)) {
        errno = ENOENT;
        return nullptr;
    }
    const char *redirected = IO::redirectPath(name);
    return orig_opendir(redirected);
}

static int new_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_faccessat(dirfd, redirected, mode, flags);
}

static int new_access(const char *pathname, int mode) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_access(redirected, mode);
}

static int new_fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_fstatat(dirfd, redirected, statbuf, flags);
}

static int new_fstatat64(int dirfd, const char *pathname, struct stat64 *statbuf, int flags) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_fstatat64(dirfd, redirected, statbuf, flags);
}

static int new_stat(const char *pathname, struct stat *statbuf) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_stat(redirected, statbuf);
}

static int new_lstat(const char *pathname, struct stat *statbuf) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_lstat(redirected, statbuf);
}

static int new_unlinkat(int dirfd, const char *pathname, int flags) {
    const char *redirected = IO::redirectPath(pathname);
    return orig_unlinkat(dirfd, redirected, flags);
}

static int new_unlink(const char *pathname) {
    const char *redirected = IO::redirectPath(pathname);
    return orig_unlink(redirected);
}

static int new_rmdir(const char *pathname) {
    const char *redirected = IO::redirectPath(pathname);
    return orig_rmdir(redirected);
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
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_readlinkat(dirfd, redirected, buf, bufsiz);
}

static ssize_t new_readlink(const char *pathname, char *buf, size_t bufsiz) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_readlink(redirected, buf, bufsiz);
}

static int new_inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
    if (pathname && (strncmp(pathname, "/proc/", 6) == 0 ||
                     strstr(pathname, "/mem") != nullptr ||
                     strstr(pathname, "/maps") != nullptr ||
                     strstr(pathname, "/pagemap") != nullptr ||
                     strstr(pathname, "/task") != nullptr ||
                     strstr(pathname, "/status") != nullptr)) {
        ALOGD("FileSystemHook: Deflecting anti-GG inotify_add_watch(%s) to /dev/null", pathname);
        return orig_inotify_add_watch(fd, "/dev/null", mask);
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_inotify_add_watch(fd, redirected, mask);
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
}
