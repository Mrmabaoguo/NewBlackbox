package top.niunaijun.blackboxa.view.setting

import android.os.Bundle
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import top.niunaijun.blackbox.BlackBoxCore
import top.niunaijun.blackboxa.R
import top.niunaijun.blackboxa.app.AppManager
import top.niunaijun.blackboxa.util.toast
import top.niunaijun.blackboxa.view.gms.GmsManagerActivity

class SettingFragment : PreferenceFragmentCompat() {

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.setting, rootKey)

        initGms()

        invalidHideState {
            val ggPreference: androidx.preference.SwitchPreferenceCompat = (findPreference("gg_compat_mode")!!)
            val ggEnable = AppManager.mBlackBoxLoader.ggCompatMode()
            ggPreference.isChecked = ggEnable
            ggPreference
        }

        invalidHideState {
            val antiCheatPreference: androidx.preference.SwitchPreferenceCompat = (findPreference("anti_cheat_bypass")!!)
            val antiCheatEnable = AppManager.mBlackBoxLoader.antiCheatBypass()
            antiCheatPreference.isChecked = antiCheatEnable
            antiCheatPreference
        }

        initAntiCheatExcludeApps()

        invalidHideState {
            val rootHidePreference: Preference = (findPreference("root_hide")!!)
            val hideRoot = AppManager.mBlackBoxLoader.hideRoot()
            rootHidePreference.setDefaultValue(hideRoot)
            rootHidePreference
        }

        invalidHideState {
            val daemonPreference: Preference = (findPreference("daemon_enable")!!)
            val mDaemonEnable = AppManager.mBlackBoxLoader.daemonEnable()
            daemonPreference.setDefaultValue(mDaemonEnable)
            daemonPreference
        }

        invalidHideState {
            val vpnPreference: Preference = (findPreference("use_vpn_network")!!)
            val mUseVpnNetwork = AppManager.mBlackBoxLoader.useVpnNetwork()
            vpnPreference.setDefaultValue(mUseVpnNetwork)
            vpnPreference
        }

        invalidHideState {
            val disableFlagSecurePreference: Preference = (findPreference("disable_flag_secure")!!)
            val mDisableFlagSecure = AppManager.mBlackBoxLoader.disableFlagSecure()
            disableFlagSecurePreference.setDefaultValue(mDisableFlagSecure)
            disableFlagSecurePreference
        }

        initSendLogs()
    }

    private fun initGms() {
        val gmsManagerPreference: Preference = (findPreference("gms_manager")!!)

        if (BlackBoxCore.get().isSupportGms) {

            gmsManagerPreference.setOnPreferenceClickListener {
                GmsManagerActivity.start(requireContext())
                true
            }
        } else {
            gmsManagerPreference.summary = getString(R.string.no_gms)
            gmsManagerPreference.isEnabled = false
        }
    }

    private fun invalidHideState(block: () -> Preference) {
        val pref = block()
        pref.setOnPreferenceChangeListener { preference, newValue ->
            val tmpHide = (newValue == true)
            when (preference.key) {
                "gg_compat_mode" -> {
                    AppManager.mBlackBoxLoader.invalidGGCompatMode(tmpHide)
                    stopVirtualAppProcesses()
                }
                "anti_cheat_bypass" -> {
                    AppManager.mBlackBoxLoader.invalidAntiCheatBypass(tmpHide)
                    stopVirtualAppProcesses()
                }
                "root_hide" -> {

                    AppManager.mBlackBoxLoader.invalidHideRoot(tmpHide)
                }
                "daemon_enable" -> {
                    AppManager.mBlackBoxLoader.invalidDaemonEnable(tmpHide)
                }
                "use_vpn_network" -> {
                    AppManager.mBlackBoxLoader.invalidUseVpnNetwork(tmpHide)
                }
                "disable_flag_secure" -> {
                    AppManager.mBlackBoxLoader.invalidDisableFlagSecure(tmpHide)
                }
            }

            toast(R.string.restart_module)
            return@setOnPreferenceChangeListener true
        }
    }

    private fun stopVirtualAppProcesses() {
        try {
            val am = requireContext().getSystemService(android.content.Context.ACTIVITY_SERVICE) as? android.app.ActivityManager
            val hostPkg = requireContext().packageName
            am?.runningAppProcesses?.forEach { proc ->
                if (proc.processName != null && proc.processName.startsWith("$hostPkg:p")) {
                    android.os.Process.killProcess(proc.pid)
                }
            }
        } catch (ignored: Throwable) {
        }
    }

    private fun initAntiCheatExcludeApps() {
        val excludePref: Preference = findPreference("anti_cheat_exclude_apps") ?: return
        updateExcludeSummary(excludePref)
        excludePref.setOnPreferenceClickListener {
            showExcludeAppsDialog(excludePref)
            true
        }
    }

    private fun updateExcludeSummary(excludePref: Preference) {
        val excluded = top.niunaijun.blackbox.core.env.BEnvironment.getAntiCheatExcludedPackages()
        if (excluded.isEmpty()) {
            excludePref.summary = getString(R.string.anti_cheat_exclude_apps_summary)
        } else {
            excludePref.summary = "已排除 (${excluded.size}): " + excluded.joinToString(", ")
        }
    }

    private fun showExcludeAppsDialog(excludePref: Preference) {
        val pkgToLabel = linkedMapOf<String, String>()
        try {
            val core = BlackBoxCore.get()
            val users = core.users
            val userIds = if (users.isNullOrEmpty()) listOf(0) else users.map { it.id }
            for (uid in userIds) {
                val apps = core.getInstalledApplications(0, uid) ?: continue
                for (app in apps) {
                    val pkg = app.packageName ?: continue
                    if (core.isBlackBoxApp(pkg)) continue
                    if (!pkgToLabel.containsKey(pkg)) {
                        val label = try {
                            BlackBoxCore.getPackageManager().getApplicationLabel(app).toString()
                        } catch (e: Exception) {
                            pkg
                        }
                        pkgToLabel[pkg] = "$label ($pkg)"
                    }
                }
            }
            val appRoot = top.niunaijun.blackbox.core.env.BEnvironment.getAppRootDir()
            appRoot.listFiles()?.forEach { dir ->
                if (dir.isDirectory) {
                    val pkg = dir.name
                    if (!pkg.isNullOrBlank() && !core.isBlackBoxApp(pkg) && !pkgToLabel.containsKey(pkg)) {
                        pkgToLabel[pkg] = pkg
                    }
                }
            }
        } catch (ignored: Throwable) {
        }

        if (pkgToLabel.isEmpty()) {
            toast(R.string.empty_empty)
            return
        }

        val pkgList = pkgToLabel.keys.toList()
        val displayItems = pkgList.map { pkgToLabel[it] ?: it }.toTypedArray()
        val currentExcluded = top.niunaijun.blackbox.core.env.BEnvironment.getAntiCheatExcludedPackages().toMutableSet()
        val checkedItems = BooleanArray(pkgList.size) { idx -> currentExcluded.contains(pkgList[idx]) }

        androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle(R.string.anti_cheat_exclude_apps)
                .setMultiChoiceItems(displayItems, checkedItems) { _, which, isChecked ->
                    val pkg = pkgList[which]
                    if (isChecked) {
                        currentExcluded.add(pkg)
                    } else {
                        currentExcluded.remove(pkg)
                    }
                }
                .setPositiveButton(R.string.done) { _, _ ->
                    top.niunaijun.blackbox.core.env.BEnvironment.setAntiCheatExcludedPackages(currentExcluded)
                    updateExcludeSummary(excludePref)
                    stopVirtualAppProcesses()
                    toast(R.string.restart_module)
                }
                .setNegativeButton(R.string.cancel, null)
                .show()
    }

    private fun initSendLogs() {
        val sendLogsPreference: Preference? = findPreference("send_logs")
        sendLogsPreference?.setOnPreferenceClickListener {
            it.isEnabled = false
            BlackBoxCore.get()
                    .sendLogs(
                            "Manual Log Upload from Settings",
                            true,
                            object : BlackBoxCore.LogSendListener {
                                override fun onSuccess() {
                                    activity?.runOnUiThread { sendLogsPreference.isEnabled = true }
                                }

                                override fun onFailure(error: String?) {
                                    activity?.runOnUiThread { sendLogsPreference.isEnabled = true }
                                }
                            }
                    )
            toast("Sending logs... (Check notifications for status)")
            true
        }
    }
}
