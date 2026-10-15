"""
BackupSuggestionGenerateHandler

Based ondetectiontoVulnerabilityGenerateSystemBackupandRestoreSuggestion。
"""
from typing import List
from ..core.kernel_info import KernelInfo


class BackupAdvisor:
    """BackupSuggestionGenerateHandler"""

    def generate_backup_steps(self, kernel_info: KernelInfo) -> List[str]:
        """Generate generic Backup steps"""
        version = kernel_info.version
        steps = [
            "# 1. Backup key Configuration Files",
            "cp -a /etc /etc.bak.$(date +%Y%m%d)",
            "cp -a /boot/grub /boot/grub.bak.$(date +%Y%m%d)",
            "",
            "# 2. BackupCurrentKernel",
            f"cp /boot/vmlinuz-{version} /boot/vmlinuz-{version}.bak",
            f"cp /boot/initrd.img-{version} /boot/initrd.img-{version}.bak 2>/dev/null || true",
            "",
            "# 3. Confirm GRUB has old Kernel for rollback",
            "grep -c 'menuentry' /boot/grub/grub.cfg",
            "",
            "# 4. SuggestionCreate磁盘Snapshot（such asUsefor LVM）",
            "# lvcreate --snapshot --name snap_before_fix --size 10G /dev/vg0/root",
            "",
            "# 5. RecordCurrentKernelParameter",
            "cat /proc/cmdline > /root/kernel_cmdline_backup.txt",
            "sysctl -a > /root/sysctl_backup.txt 2>/dev/null",
        ]
        return steps

    def generate_rollback_steps(self, kernel_info: KernelInfo) -> List[str]:
        """GenerateRollback steps"""
        return [
            "# such asResultUpgradeAfterSystemAnomaly，ExecuteBelowRollback:",
            "# 1. Select old kernel in GRUB during restart",
            "# 2. orModify /etc/default/grub 指定旧Kernel:",
            "#    GRUB_DEFAULT='Advanced options for Ubuntu>Ubuntu, with Linux <old-version>'",
            "#    update-grub",
            "# 3. RestoreConfigurationFile:",
            "#    cp -a /etc.bak.<date>/* /etc/",
            "# 4. such ashas LVM Snapshot:",
            "#    lvconvert --merge /dev/vg0/snap_before_fix",
        ]

    def generate_kernel_recovery_info(self) -> str:
        """GenerateKernelRestoreMode说明"""
        return (
            "KernelRestoreMode:\n"
            "1. RestartSystem，in GRUB 菜单By ESC or长By Shift\n"
            "2. 选择 'Advanced options'\n"
            "3. 选择带 '(recovery mode)' 旧Kernel\n"
            "4. inRestore菜单in选择 'root' Enter root shell\n"
            "5. Execute必needRollbackOperation\n"
            "6. Restart: reboot"
        )
