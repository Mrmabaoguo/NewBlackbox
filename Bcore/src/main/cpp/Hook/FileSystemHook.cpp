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
#include <pthread.h>
#include <dlfcn.h>
#include <time.h>
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
static int (*orig_closedir)(DIR *dirp) = nullptr;
static struct dirent *(*orig_readdir)(DIR *dirp) = nullptr;
static struct dirent64 *(*orig_readdir64)(DIR *dirp) = nullptr;

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
static int (*orig_mincore)(void *addr, size_t length, unsigned char *vec) = nullptr;

static int (*orig_pthread_cond_broadcast)(pthread_cond_t *cond) = nullptr;
static int (*orig_pthread_mutex_unlock)(pthread_mutex_t *mutex) = nullptr;

// Track open DIR* handles for "/proc" so readdir/readdir64 can hide other PIDs (such as GG and lib5.so daemon)
static DIR *g_proc_dirs[16] = {nullptr};

static void register_proc_dir(DIR *dirp) {
    if (!dirp) return;
    for (int i = 0; i < 16; ++i) {
        if (__sync_bool_compare_and_swap(&g_proc_dirs[i], nullptr, dirp)) {
            return;
        }
    }
    g_proc_dirs[0] = dirp;
}

static void unregister_proc_dir(DIR *dirp) {
    if (!dirp) return;
    for (int i = 0; i < 16; ++i) {
        __sync_bool_compare_and_swap(&g_proc_dirs[i], dirp, nullptr);
    }
}

static bool is_proc_dir(DIR *dirp) {
    if (!dirp) return false;
    for (int i = 0; i < 16; ++i) {
        if (g_proc_dirs[i] == dirp) return true;
    }
    return false;
}

static bool is_other_pid_name(const char *d_name) {
    if (!d_name || d_name[0] < '1' || d_name[0] > '9') return false;
    int pid = 0;
    for (const char *p = d_name; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        pid = pid * 10 + (*p - '0');
    }
    return (pid > 0 && pid != (int) getpid());
}

static bool is_own_pid_or_tid(int id) {
    if (id <= 0) return false;
    if (id == (int) getpid()) return true;
    char task_path[64];
    snprintf(task_path, sizeof(task_path), "/proc/self/task/%d", id);
    if (orig_faccessat) {
        return orig_faccessat(AT_FDCWD, task_path, F_OK, 0) == 0;
    }
    return false;
}

static bool is_problematic_path(int dirfd, const char *pathname) {
    if (!pathname || g_is_excluded_app) return false;
    // Block the game's anti-cheat from scanning /proc/<other_pid>/... (such as GG or GG's lib5.so daemon sharing the same UID)
    if (strncmp(pathname, "/proc/", 6) == 0) {
        char c = pathname[6];
        if (c >= '1' && c <= '9') {
            int target_pid = atoi(pathname + 6);
            if (target_pid > 0 && !is_own_pid_or_tid(target_pid)) {
                return true;
            }
        }
        return false;
    }
    // Block relative <other_pid>/cmdline, <other_pid>/maps, <other_pid>/status, etc. when dirfd is /proc
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
                          strcmp(p + 1, "smaps") == 0 ||
                          strcmp(p + 1, "wchan") == 0 ||
                          strcmp(p + 1, "mem") == 0 ||
                          strcmp(p + 1, "pagemap") == 0 ||
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

static bool is_proc_pagemap_path(const char *pathname) {
    return is_proc_suffix_path(pathname, "/pagemap", 8);
}

static bool is_self_maps_path(const char *pathname) {
    if (!pathname || g_is_excluded_app) return false;
    if (strcmp(pathname, "/proc/self/maps") == 0 ||
        strcmp(pathname, "/proc/thread-self/maps") == 0) {
        return true;
    }
    if (strncmp(pathname, "/proc/", 6) == 0) {
        char self_maps[64];
        snprintf(self_maps, sizeof(self_maps), "/proc/%d/maps", (int) getpid());
        if (strcmp(pathname, self_maps) == 0) {
            return true;
        }
    }
    return false;
}

static int open_filtered_status_fd(int dirfd, const char *status_path) {
    if (!orig_openat) return -1;
    int real_fd = orig_openat(dirfd, status_path, O_RDONLY | O_CLOEXEC, 0);
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

static int open_filtered_stat_fd(int dirfd, const char *stat_path) {
    if (!orig_openat) return -1;
    int real_fd = orig_openat(dirfd, stat_path, O_RDONLY | O_CLOEXEC, 0);
    if (real_fd < 0) return -1;

    int mem_fd = -1;
#if defined(__NR_memfd_create)
    mem_fd = (int) syscall(__NR_memfd_create, "anon_stat", 1 /* MFD_CLOEXEC */);
#endif
    if (mem_fd < 0) {
        close(real_fd);
        return -1;
    }

    char buf[1024];
    ssize_t n = read(real_fd, buf, sizeof(buf) - 1);
    close(real_fd);
    if (n <= 0) {
        close(mem_fd);
        return -1;
    }
    buf[n] = '\0';

    char *last_paren = strrchr(buf, ')');
    if (last_paren && last_paren[1] == ' ') {
        char st = last_paren[2];
        if (st == 'T' || st == 't') {
            last_paren[2] = 'S';
        }
    }

    write(mem_fd, buf, (size_t) n);
    lseek(mem_fd, 0, SEEK_SET);
    return mem_fd;
}

static int open_filtered_wchan_fd() {
    int mem_fd = -1;
#if defined(__NR_memfd_create)
    mem_fd = (int) syscall(__NR_memfd_create, "anon_wchan", 1 /* MFD_CLOEXEC */);
#endif
    if (mem_fd < 0) return -1;
    write(mem_fd, "0", 1);
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
                if (prefix_len + strlen(after_bb) < sizeof(out_line)) {
                    memcpy(out_line, line, prefix_len);
                    strcpy(out_line + prefix_len, after_bb);
                    write(mem_fd, out_line, strlen(out_line));
                    continue;
                }
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

static bool raw_path_exists(int dirfd, const char *pathname) {
    if (!pathname) return false;
    struct stat st{};
    if (orig_fstatat && orig_fstatat(dirfd, pathname, &st, 0) == 0) {
        return true;
    }
    if (orig_faccessat && orig_faccessat(dirfd, pathname, F_OK, 0) == 0) {
        return true;
    }
    return is_system_root_prefix(pathname);
}

static void ensure_parent_dirs(const char *filepath) {
    if (!filepath || !orig_mkdirat || strstr(filepath, "/blackbox/") == nullptr) {
        return;
    }
    char tmp[4096];
    size_t len = strlen(filepath);
    if (len >= sizeof(tmp)) return;
    memcpy(tmp, filepath, len + 1);
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (strstr(tmp, "/blackbox") != nullptr) {
                orig_mkdirat(AT_FDCWD, tmp, 0771);
            }
            *p = '/';
        }
    }
}

static int handle_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    if (!pathname) {
        return orig_mkdirat(dirfd, pathname, mode);
    }
    const char *redirected = IO::redirectPath(pathname);
    int ret = orig_mkdirat(dirfd, redirected, mode);
    if (ret == -1 && errno == ENOENT && strstr(redirected, "/blackbox/") != nullptr) {
        ensure_parent_dirs(redirected);
        ret = orig_mkdirat(dirfd, redirected, mode);
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
    return handle_mkdirat(dirfd, pathname, mode);
}

static int new_mkdir(const char *pathname, mode_t mode) {
    if (orig_mkdirat) {
        return handle_mkdirat(AT_FDCWD, pathname, mode);
    }
    const char *redirected = IO::redirectPath(pathname);
    int ret = orig_mkdir(redirected, mode);
    if (ret == -1 && (errno == EACCES || errno == EPERM || errno == EROFS)) {
        if (raw_path_exists(AT_FDCWD, redirected)) {
            errno = EEXIST;
        }
    }
    return ret;
}

static int handle_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    if (is_problematic_path(dirfd, pathname)) {
        errno = ENOENT;
        return -1;
    }
    if (is_proc_pagemap_path(pathname)) {
        errno = EACCES;
        return -1;
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

static int new_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, unsigned int);
        va_end(args);
    }
    return handle_openat(dirfd, pathname, flags, mode);
}

static int new_openat64(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, unsigned int);
        va_end(args);
    }
    if (orig_openat) {
        return handle_openat(dirfd, pathname, flags, mode);
    }
    if (is_problematic_path(dirfd, pathname)) {
        errno = ENOENT;
        return -1;
    }
    if (is_proc_pagemap_path(pathname)) {
        errno = EACCES;
        return -1;
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
    if (orig_openat) {
        return handle_openat(dirfd, pathname, flags, 0);
    }
    if (is_problematic_path(dirfd, pathname)) {
        errno = ENOENT;
        return -1;
    }
    if (is_proc_pagemap_path(pathname)) {
        errno = EACCES;
        return -1;
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
    if (orig_openat) {
        return handle_openat(AT_FDCWD, pathname, flags, mode);
    }
    if (is_problematic_path(AT_FDCWD, pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_open(redirected, flags, mode);
}

static int new_open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t) va_arg(args, unsigned int);
        va_end(args);
    }
    if (orig_openat) {
        return handle_openat(AT_FDCWD, pathname, flags, mode);
    }
    if (is_problematic_path(AT_FDCWD, pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_open64(redirected, flags, mode);
}

static int new___open_2(const char *pathname, int flags) {
    if (orig_openat) {
        return handle_openat(AT_FDCWD, pathname, flags, 0);
    }
    if (is_problematic_path(AT_FDCWD, pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig___open_2(redirected, flags);
}

static FILE *new_fopen(const char *pathname, const char *mode) {
    if (is_problematic_path(AT_FDCWD, pathname)) {
        errno = ENOENT;
        return nullptr;
    }
    if (is_proc_pagemap_path(pathname)) {
        errno = EACCES;
        return nullptr;
    }
    if (is_proc_status_path(pathname)) {
        int sfd = open_filtered_status_fd(AT_FDCWD, pathname);
        if (sfd >= 0) {
            FILE *sfp = fdopen(sfd, mode ? mode : "r");
            if (sfp) return sfp;
            close(sfd);
        }
    }
    if (is_proc_stat_path(pathname)) {
        int stfd = open_filtered_stat_fd(AT_FDCWD, pathname);
        if (stfd >= 0) {
            FILE *stfp = fdopen(stfd, mode ? mode : "r");
            if (stfp) return stfp;
            close(stfd);
        }
    }
    if (is_proc_wchan_path(pathname)) {
        int wfd = open_filtered_wchan_fd();
        if (wfd >= 0) {
            FILE *wfp = fdopen(wfd, mode ? mode : "r");
            if (wfp) return wfp;
            close(wfd);
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
    if (is_problematic_path(AT_FDCWD, name)) {
        errno = ENOENT;
        return nullptr;
    }
    const char *redirected = IO::redirectPath(name);
    DIR *dirp = orig_opendir(redirected);
    if (dirp && !g_is_excluded_app && name &&
        (strcmp(name, "/proc") == 0 || strcmp(name, "/proc/") == 0)) {
        register_proc_dir(dirp);
    }
    return dirp;
}

static int new_closedir(DIR *dirp) {
    unregister_proc_dir(dirp);
    return orig_closedir(dirp);
}

static struct dirent *new_readdir(DIR *dirp) {
    bool filter_proc = (!g_is_excluded_app && is_proc_dir(dirp));
    while (true) {
        struct dirent *ent = orig_readdir(dirp);
        if (!ent) return nullptr;
        if (filter_proc && is_other_pid_name(ent->d_name)) {
            continue;
        }
        return ent;
    }
}

static struct dirent64 *new_readdir64(DIR *dirp) {
    bool filter_proc = (!g_is_excluded_app && is_proc_dir(dirp));
    while (true) {
        struct dirent64 *ent = orig_readdir64(dirp);
        if (!ent) return nullptr;
        if (filter_proc && is_other_pid_name(ent->d_name)) {
            continue;
        }
        return ent;
    }
}

static int new_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (is_problematic_path(dirfd, pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_faccessat(dirfd, redirected, mode, flags);
}

static int new_access(const char *pathname, int mode) {
    if (orig_faccessat) {
        return new_faccessat(AT_FDCWD, pathname, mode, 0);
    }
    if (is_problematic_path(AT_FDCWD, pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_access(redirected, mode);
}

static int new_fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    if (is_problematic_path(dirfd, pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_fstatat(dirfd, redirected, statbuf, flags);
}

static int new_fstatat64(int dirfd, const char *pathname, struct stat64 *statbuf, int flags) {
    if (is_problematic_path(dirfd, pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_fstatat64(dirfd, redirected, statbuf, flags);
}

static int new_stat(const char *pathname, struct stat *statbuf) {
    if (orig_fstatat) {
        return new_fstatat(AT_FDCWD, pathname, statbuf, 0);
    }
    if (is_problematic_path(AT_FDCWD, pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_stat(redirected, statbuf);
}

static int new_lstat(const char *pathname, struct stat *statbuf) {
    if (orig_fstatat) {
        return new_fstatat(AT_FDCWD, pathname, statbuf, AT_SYMLINK_NOFOLLOW);
    }
    if (is_problematic_path(AT_FDCWD, pathname)) {
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
    if (orig_unlinkat) {
        return new_unlinkat(AT_FDCWD, pathname, 0);
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_unlink(redirected);
}

static int new_rmdir(const char *pathname) {
    if (orig_unlinkat) {
        return new_unlinkat(AT_FDCWD, pathname, AT_REMOVEDIR);
    }
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
    if (orig_renameat) {
        return new_renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath);
    }
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
    if (orig_fchmodat) {
        return new_fchmodat(AT_FDCWD, pathname, mode, 0);
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_chmod(redirected, mode);
}

static ssize_t new_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    if (is_problematic_path(dirfd, pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    ssize_t ret = orig_readlinkat(dirfd, redirected, buf, bufsiz);
    if (ret > 0 && buf && bufsiz > 0) {
        char tmp[4096];
        size_t copy_len = ((size_t) ret < sizeof(tmp) - 1) ? (size_t) ret : (sizeof(tmp) - 1);
        memcpy(tmp, buf, copy_len);
        tmp[copy_len] = '\0';

        // Spoof memfd symlink target to real kernel procfs dentry format "/proc/<numeric_pid>/..."
        if (strncmp(tmp, "/memfd:anon_", 12) == 0) {
            const char *leaf = "status";
            if (strstr(tmp, "anon_stat") && !strstr(tmp, "anon_status")) {
                leaf = "stat";
            } else if (strstr(tmp, "anon_wchan")) {
                leaf = "wchan";
            } else if (strstr(tmp, "anon_maps")) {
                leaf = "maps";
            }
            char fake_target[64];
            int flen = snprintf(fake_target, sizeof(fake_target), "/proc/%d/%s", (int) getpid(), leaf);
            if (flen > 0) {
                size_t out_len = ((size_t) flen < bufsiz) ? (size_t) flen : bufsiz;
                memcpy(buf, fake_target, out_len);
                return (ssize_t) out_len;
            }
        }

        // If the resolved symlink target contains /data/.../blackbox/data/..., strip the /blackbox prefix
        const char *bb_marker = strstr(tmp, "/blackbox/data/");
        if (bb_marker != nullptr) {
            const char *after_bb = bb_marker + strlen("/blackbox");
            size_t new_len = strlen(after_bb);
            if (new_len > bufsiz) new_len = bufsiz;
            memcpy(buf, after_bb, new_len);
            return (ssize_t) new_len;
        }
    }
    return ret;
}

static ssize_t new_readlink(const char *pathname, char *buf, size_t bufsiz) {
    if (orig_readlinkat) {
        return new_readlinkat(AT_FDCWD, pathname, buf, bufsiz);
    }
    if (is_problematic_path(AT_FDCWD, pathname)) {
        errno = ENOENT;
        return -1;
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_readlink(redirected, buf, bufsiz);
}

static int new_inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
    // Prevent anti-cheat (e.g. libthemis.so / libtersafe2.so) from placing inotify watchers on /proc/self/mem, /proc/self/maps, /proc/self/pagemap, /proc/self/task
    if (pathname && (strncmp(pathname, "/proc/", 6) == 0 ||
                     strstr(pathname, "/mem") != nullptr ||
                     strstr(pathname, "/maps") != nullptr ||
                     strstr(pathname, "/pagemap") != nullptr ||
                     strstr(pathname, "/task") != nullptr ||
                     strstr(pathname, "/status") != nullptr ||
                     strstr(pathname, "/stat") != nullptr)) {
        return orig_inotify_add_watch(fd, "/dev/null", mask);
    }
    const char *redirected = IO::redirectPath(pathname);
    return orig_inotify_add_watch(fd, redirected, mask);
}

// Neutralize mincore() honey-pot memory page traps (StartMemoryTracker / libtersafe2.so / libtprt.so):
// Anti-cheat allocates untouched anonymous rw-p pages and polls mincore(); when GG scans memory via /proc/<pid>/mem,
// the kernel faults those pages into RAM (vec[i] |= 1). Reporting vec[i] = 0 hides external memory scans completely.
static int new_mincore(void *addr, size_t length, unsigned char *vec) {
    int ret = orig_mincore ? orig_mincore(addr, length, vec) : -1;
    if (ret == 0 && vec != nullptr && !g_is_excluded_app) {
        long page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0) page_size = 4096;
        size_t num_pages = (length + (size_t) page_size - 1) / (size_t) page_size;
        memset(vec, 0, num_pages);
    }
    return ret;
}

// Neutralize libthemis.so background watchdog thread (0xc1240) AFTER its 1st login iteration completes:
// At login ("正在进入游戏"), 0xc18d8 spawns 0xc1240 and waits on condvar 0xd90f0 for the 1st iteration to generate
// the 32-byte type-4 token, call pthread_cond_broadcast(0xd90f0) at 0xc1684, and call pthread_mutex_unlock(0xd90c8) at 0xc1690.
// Right after 0xc1690, 0xc1240 loops in nanosleep (0xc16dc: svc #0) and wakes up on EINTR (errno == 4) whenever GG attaches
// ptrace during a memory search, immediately calling 0x3b918 -> 0x3b788 -> 0xbf448 -> exit(1).
// By freezing 0xc1240 inside pthread_mutex_unlock right after it broadcasts 0xd90f0 and unlocks 0xd90c8,
// login ("正在进入游戏") succeeds 100% AND 0xc1240 never executes a 2nd scan when GG searches memory!
static thread_local bool t_themis_watchdog_broadcasted = false;

static bool is_caller_in_libthemis(void *ret_addr) {
    if (!ret_addr) return false;
    Dl_info info{};
    if (dladdr(ret_addr, &info) != 0 && info.dli_fname) {
        if (strstr(info.dli_fname, "libthemis.so") != nullptr) {
            return true;
        }
    }
    return false;
}

static int new_pthread_cond_broadcast(pthread_cond_t *cond) {
    int ret = orig_pthread_cond_broadcast(cond);
    if (!g_is_excluded_app && is_caller_in_libthemis(__builtin_return_address(0))) {
        t_themis_watchdog_broadcasted = true;
    }
    return ret;
}

static int new_pthread_mutex_unlock(pthread_mutex_t *mutex) {
    int ret = orig_pthread_mutex_unlock(mutex);
    if (t_themis_watchdog_broadcasted && !g_is_excluded_app && is_caller_in_libthemis(__builtin_return_address(0))) {
        ALOGD("FileSystemHook: Freezing libthemis.so background watchdog thread 0xc1240 (tid=%d) after 1st login iteration", (int) gettid());
        while (true) {
            struct timespec ts = {3600, 0};
            nanosleep(&ts, nullptr);
        }
    }
    return ret;
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
    hook_libc_symbol(handle, "mincore", (void *) new_mincore, (void **) &orig_mincore);

    // Hook non-*at functions & directory iterators
    hook_libc_symbol(handle, "mkdir", (void *) new_mkdir, (void **) &orig_mkdir);
    hook_libc_symbol(handle, "open", (void *) new_open, (void **) &orig_open);
    hook_libc_symbol(handle, "open64", (void *) new_open64, (void **) &orig_open64);
    hook_libc_symbol(handle, "__open_2", (void *) new___open_2, (void **) &orig___open_2);
    hook_libc_symbol(handle, "fopen", (void *) new_fopen, (void **) &orig_fopen);
    hook_libc_symbol(handle, "opendir", (void *) new_opendir, (void **) &orig_opendir);
    hook_libc_symbol(handle, "closedir", (void *) new_closedir, (void **) &orig_closedir);
    hook_libc_symbol(handle, "readdir", (void *) new_readdir, (void **) &orig_readdir);
    hook_libc_symbol(handle, "readdir64", (void *) new_readdir64, (void **) &orig_readdir64);
    hook_libc_symbol(handle, "access", (void *) new_access, (void **) &orig_access);
    hook_libc_symbol(handle, "stat", (void *) new_stat, (void **) &orig_stat);
    hook_libc_symbol(handle, "lstat", (void *) new_lstat, (void **) &orig_lstat);
    hook_libc_symbol(handle, "unlink", (void *) new_unlink, (void **) &orig_unlink);
    hook_libc_symbol(handle, "rmdir", (void *) new_rmdir, (void **) &orig_rmdir);
    hook_libc_symbol(handle, "rename", (void *) new_rename, (void **) &orig_rename);
    hook_libc_symbol(handle, "chmod", (void *) new_chmod, (void **) &orig_chmod);
    hook_libc_symbol(handle, "readlink", (void *) new_readlink, (void **) &orig_readlink);

    // Hook pthread synchronization to freeze libthemis.so's 0xc1240 watchdog thread after its 1st login iteration
    hook_libc_symbol(handle, "pthread_cond_broadcast", (void *) new_pthread_cond_broadcast, (void **) &orig_pthread_cond_broadcast);
    hook_libc_symbol(handle, "pthread_mutex_unlock", (void *) new_pthread_mutex_unlock, (void **) &orig_pthread_mutex_unlock);

    xdl_close(handle);
}
