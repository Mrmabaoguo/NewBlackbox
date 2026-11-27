



#include "IO.h"
#include "Log.h"
#include <cstring>
#include <cstdlib>

jmethodID getAbsolutePathMethodId;

list<IO::RelocateInfo> relocate_rule;

char *replace(const char *str, const char *src, const char *dst) {
    const char *pos = str;
    int count = 0;
    size_t src_len = strlen(src);
    size_t dst_len = strlen(dst);
    if (src_len == 0) {
        return strdup(str);
    }
    while ((pos = strstr(pos, src))) {
        count++;
        pos += src_len;
    }

    size_t result_len = strlen(str) + (dst_len - src_len) * count + 1;
    char *result = (char *) malloc(result_len);
    if (!result) {
        return (char *) str;
    }
    memset(result, 0, result_len);

    const char *left = str;
    const char *right = nullptr;

    while ((right = strstr(left, src))) {
        strncat(result, left, right - left);
        strcat(result, dst);
        right += src_len;
        left = right;
    }
    strcat(result, left);
    return result;
}

const char *IO::redirectPathBuf(const char *__path, char *buf, size_t buf_size) {
    if (__path == nullptr || buf == nullptr || buf_size == 0) {
        return __path;
    }
    if (strncmp(__path, "/proc/", 6) == 0) {
        return __path;
    }
    if (strstr(__path, "/blackbox/") != nullptr) {
        return __path;
    }

    list<IO::RelocateInfo>::iterator iterator;
    for (iterator = relocate_rule.begin(); iterator != relocate_rule.end(); ++iterator) {
        IO::RelocateInfo info = *iterator;
        if (!info.targetPath || !info.relocatePath) {
            continue;
        }
        size_t target_len = strlen(info.targetPath);
        if (target_len > 0 && strncmp(__path, info.targetPath, target_len) == 0 &&
            (__path[target_len] == '\0' || __path[target_len] == '/')) {
            size_t reloc_len = strlen(info.relocatePath);
            size_t rest_len = strlen(__path + target_len);
            if (reloc_len + rest_len < buf_size - 1) {
                memcpy(buf, info.relocatePath, reloc_len);
                memcpy(buf + reloc_len, __path + target_len, rest_len + 1);
                return buf;
            }
        }
    }
    return __path;
}

const char *IO::redirectPath(const char *__path) {
    static char s_ring_buffers[16][2048];
    static volatile int s_ring_idx = 0;
    int idx = (__sync_fetch_and_add(&s_ring_idx, 1)) & 15;
    return redirectPathBuf(__path, s_ring_buffers[idx], sizeof(s_ring_buffers[idx]));
}

jstring IO::redirectPath(JNIEnv *env, jstring path) {




    return BoxCore::redirectPathString(env, path);
}

jobject IO::redirectPath(JNIEnv *env, jobject path) {






    return BoxCore::redirectPathFile(env, path);
}

void IO::addRule(const char *targetPath, const char *relocatePath) {
    IO::RelocateInfo info{};
    info.targetPath = targetPath;
    info.relocatePath = relocatePath;
    relocate_rule.push_back(info);
}

void IO::init(JNIEnv *env) {
    jclass tmpFile = env->FindClass("java/io/File");
    getAbsolutePathMethodId = env->GetMethodID(tmpFile, "getAbsolutePath", "()Ljava/lang/String;");
}
