package top.niunaijun.blackbox.core.env;

import java.io.File;
import java.util.Locale;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.app.BActivityThread;
import top.niunaijun.blackbox.utils.FileUtils;


public class BEnvironment {
    private static final File sVirtualRoot = new File(BlackBoxCore.getContext().getCacheDir().getParent(), "blackbox");
    private static final File sExternalVirtualRoot = BlackBoxCore.getContext().getExternalFilesDir("blackbox");

    public static File JUNIT_JAR = new File(getCacheDir(), "junit.apk");
    public static File EMPTY_JAR = new File(getCacheDir(), "empty.apk");

    public static void load() {
        FileUtils.mkdirs(sVirtualRoot);
        FileUtils.mkdirs(sExternalVirtualRoot);
        FileUtils.mkdirs(getSystemDir());
        FileUtils.mkdirs(getCacheDir());
        FileUtils.mkdirs(getProcDir());
    }

    public static File getVirtualRoot() {
        return sVirtualRoot;
    }

    public static File getExternalVirtualRoot() {
        return sExternalVirtualRoot;
    }

    public static File getSystemDir() {
        return new File(sVirtualRoot, "system");
    }

    public static File getProcDir() {
        return new File(sVirtualRoot, "proc");
    }

    public static File getCacheDir() {
        return new File(sVirtualRoot, "cache");
    }

    public static File getUserInfoConf() {
        return new File(getSystemDir(), "user.conf");
    }

    public static File getAccountsConf() {
        return new File(getSystemDir(), "accounts.conf");
    }

    public static File getUidConf() {
        return new File(getSystemDir(), "uid.conf");
    }

    public static File getSharedUserConf() {
        return new File(getSystemDir(), "shared-user.conf");
    }

    public static File getXPModuleConf() {
        return new File(getSystemDir(), "xposed-module.conf");
    }

    public static File getFakeLocationConf() {
        return new File(getSystemDir(), "fake-location.conf");
    }

    public static File getPackageConf(String packageName) {
        return new File(getAppDir(packageName), "package.conf");
    }

    public static File getExternalUserDir(int userId) {
        return new File(sExternalVirtualRoot, String.format(Locale.CHINA, "storage/emulated/%d/", userId));
    }

    public static File getUserDir(int userId) {
        return new File(sVirtualRoot, String.format(Locale.CHINA, "data/user/%d", userId));
    }

    public static File getExternalObbDir(String packageName, int userId) {
        return new File(getExternalUserDir(userId), String.format(Locale.CHINA, "Android/obb/%s", packageName));
    }


    public static File getDeDataDir(String packageName, int userId) {
        return new File(sVirtualRoot, String.format(Locale.CHINA, "data/user_de/%d/%s", userId, packageName));
    }

    public static File getExternalDataDir(String packageName, int userId) {
        return new File(getExternalUserDir(userId), String.format(Locale.CHINA, "Android/data/%s", packageName));
    }


    public static File getDataDir(String packageName, int userId) {
        return new File(sVirtualRoot, String.format(Locale.CHINA, "data/user/%d/%s", userId, packageName));
    }

    public static File getProcDir(int pid) {
        File file = new File(getProcDir(), String.format(Locale.CHINA, "%d", pid));
        FileUtils.mkdirs(file);
        return file;
    }

    public static File getExternalDataFilesDir(String packageName, int userId) {
        return new File(getExternalDataDir(packageName, userId), "files");
    }

    public static File getDataFilesDir(String packageName, int userId) {
        return new File(getDataDir(packageName, userId), "files");
    }

    public static File getExternalDataCacheDir(String packageName, int userId) {
        return new File(getExternalDataDir(packageName, userId), "cache");
    }

    public static File getDataCacheDir(String packageName, int userId) {
        return new File(getDataDir(packageName, userId), "cache");
    }

    public static File getDataLibDir(String packageName, int userId) {
        return new File(getDataDir(packageName, userId), "lib");
    }

    public static File getDataDatabasesDir(String packageName, int userId) {
        return new File(getDataDir(packageName, userId), "databases");
    }

    public static File getAppRootDir() {
        return getAppDir("");
    }

    public static File getAppDir(String packageName) {
        return new File(sVirtualRoot, "data/app/" + packageName);
    }

    public static File getBaseApkDir(String packageName) {
        return new File(sVirtualRoot, "data/app/" + packageName + "/base.apk");
    }

    public static File getAppLibDir(String packageName) {
        return new File(getAppDir(packageName), "lib");
    }

    public static File getXSharedPreferences(String packageName, String prefFileName) {
       return new File(BEnvironment.getDataDir(packageName, BlackBoxCore.getUserId()), "shared_prefs/" + prefFileName + ".xml");
    }

    public static File getGGCompatConf() {
        return new File(getSystemDir(), "gg_compat.conf");
    }

    public static File getAntiCheatBypassConf() {
        return new File(getSystemDir(), "anti_cheat_bypass.conf");
    }

    public static boolean isGGCompatEnabled() {
        try {
            File conf = getGGCompatConf();
            if (!conf.exists()) {
                return true;
            }
            java.io.FileInputStream fis = new java.io.FileInputStream(conf);
            int b = fis.read();
            fis.close();
            return b != '0';
        } catch (Throwable ignored) {
            return true;
        }
    }

    public static void setGGCompatEnabled(boolean enable) {
        try {
            FileUtils.mkdirs(getSystemDir());
            java.io.FileOutputStream fos = new java.io.FileOutputStream(getGGCompatConf(), false);
            fos.write(enable ? '1' : '0');
            fos.flush();
            fos.close();
        } catch (Throwable ignored) {
        }
    }

    public static boolean isAntiCheatBypassEnabled() {
        try {
            File conf = getAntiCheatBypassConf();
            if (!conf.exists()) {
                return true;
            }
            java.io.FileInputStream fis = new java.io.FileInputStream(conf);
            int b = fis.read();
            fis.close();
            return b != '0';
        } catch (Throwable ignored) {
            return true;
        }
    }

    public static void setAntiCheatBypassEnabled(boolean enable) {
        try {
            FileUtils.mkdirs(getSystemDir());
            java.io.FileOutputStream fos = new java.io.FileOutputStream(getAntiCheatBypassConf(), false);
            fos.write(enable ? '1' : '0');
            fos.flush();
            fos.close();
        } catch (Throwable ignored) {
        }
    }
}
