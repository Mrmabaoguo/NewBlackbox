#ifndef VIRTUALM_FILESYSTEMHOOK_H
#define VIRTUALM_FILESYSTEMHOOK_H

class FileSystemHook {
public:
    static void init();
    static void setAntiCheatBypass(bool enable, const char *packageName, bool isGameGuardian);
};

#endif
