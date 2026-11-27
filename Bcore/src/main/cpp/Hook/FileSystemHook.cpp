#include "FileSystemHook.h"
#include "IO.h"
#include "Log.h"
#include "Dobby/dobby.h"
#include "xdl.h"
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <stdarg.h>
#include <cstring>
#include <cstdlib>
#include <errno.h>

static bool g_anti_cheat_bypass_enabled = true;

void FileSystemHook::setAntiCheatBypass(bool enable, const char *packageName, bool isGameGuardian) {
    (void) packageName;
    (void) isGameGuardian;
    g_anti_cheat_bypass_enabled = enable;
    ALOGD("FileSystemHook::setAntiCheatBypass: enable=%d", enable ? 1 : 0);
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
        // Update libthemis.so's 256-byte .bss path buffer (0xd7f28) in-place when mkdir(0xd7f28, 0777) runs
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
    const char *redirected = IO::redirectPath(pathname);
    return orig___open_2(redirected, flags);
}

static FILE *new_fopen(const char *pathname, const char *mode) {
    if (is_problematic_path(pathname)) {
        errno = ENOENT;
        return nullptr;
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
    return orig_faccessat(dirfd, redirected, mode, flags);
}

static int new_access(const char *pathname, int mode) {
    const char *redirected = IO::redirectPath(pathname);
    return orig_access(redirected, mode);
}

static int new_fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    const char *redirected = IO::redirectPath(pathname);
    return orig_fstatat(dirfd, redirected, statbuf, flags);
}

static int new_fstatat64(int dirfd, const char *pathname, struct stat64 *statbuf, int flags) {
    const char *redirected = IO::redirectPath(pathname);
    return orig_fstatat64(dirfd, redirected, statbuf, flags);
}

static int new_stat(const char *pathname, struct stat *statbuf) {
    const char *redirected = IO::redirectPath(pathname);
    return orig_stat(redirected, statbuf);
}

static int new_lstat(const char *pathname, struct stat *statbuf) {
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
    const char *redirected = IO::redirectPath(pathname);
    return orig_readlinkat(dirfd, redirected, buf, bufsiz);
}

static ssize_t new_readlink(const char *pathname, char *buf, size_t bufsiz) {
    const char *redirected = IO::redirectPath(pathname);
    return orig_readlink(redirected, buf, bufsiz);
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
        // Check if this function branches directly (b or bl) to an already-hooked *at function
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
        ALOGD("FileSystemHook: Anti-cheat bypass disabled by settings");
        return;
    }

    ALOGD("FileSystemHook: Initializing file system hooks");

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

    // Hook non-*at functions (automatically skipped if they are short tail-calls into already-hooked *at functions)
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
