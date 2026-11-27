



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

const char *IO::redirectPath(const char *__path) {
    if (__path == nullptr) {
        return nullptr;
    }
    if (strncmp(__path, "/proc/", 6) == 0) {
        return __path;
    }
    if (strstr(__path, "/blackbox/") != nullptr) {
        return __path;
    }

    if (strstr(__path, "resource-cache")) {
        ALOGD("Blocking resource-cache path: %s", __path);
        return "/dev/null";
    }
    if (strstr(__path, "@idmap")) {
        ALOGD("Blocking idmap path: %s", __path);
        return "/dev/null";
    }
    if (strstr(__path, "systemui") && (strstr(__path, ".frro") || strstr(__path, "-accent-") || strstr(__path, "-dynamic-") || strstr(__path, "-neutral-"))) {
        ALOGD("Blocking systemui problematic path: %s", __path);
        return "/dev/null";
    }
    if (strstr(__path, "data@resource-cache@")) {
        ALOGD("Blocking data@resource-cache@ pattern: %s", __path);
        return "/dev/null";
    }
    if (strstr(__path, ".frro")) {
        ALOGD("Blocking .frro file: %s", __path);
        return "/dev/null";
    }
    if (strstr(__path, "systemui")) {
        ALOGD("Blocking systemui path: %s", __path);
        return "/dev/null";
    }

    static thread_local char s_tls_buffers[8][4096];
    static thread_local int s_tls_idx = 0;

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
            if (reloc_len + rest_len < sizeof(s_tls_buffers[0]) - 1) {
                char *ret = s_tls_buffers[s_tls_idx];
                s_tls_idx = (s_tls_idx + 1) & 7;
                memcpy(ret, info.relocatePath, reloc_len);
                memcpy(ret + reloc_len, __path + target_len, rest_len + 1);
                return ret;
            }
        }
    }
    return __path;
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
