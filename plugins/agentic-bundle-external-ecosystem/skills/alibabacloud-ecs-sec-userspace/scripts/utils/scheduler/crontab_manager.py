"""Crontab Manager - Manage scheduled security scans"""
import subprocess
import logging
from typing import Dict

logger = logging.getLogger("sec-userspace")


class CrontabManager:
    """Manage crontab entries for sec-userspace scheduled scans"""
    
    def __init__(self, output_dir: str = "/data/sec-userspace/workspace"):
        self.output_dir = output_dir
        self.sec_inspect_cmd = "sec-userspace"
        self.cron_entry_comment = "# sec-userspace daily scan"
        self.cron_entry_whitelist_comment = "# sec-userspace whitelist update"
    
    def generate_crontab(self, mode: str = "daily", hour: int = 2, 
                        minute: int = 0) -> str:
        """
        Generate crontab entry for sec-userspace
        
        Args:
            mode: Scan mode (daily, weekly)
            hour: Hour to run (0-23)
            minute: Minute to run (0-59)
        
        Returns:
            Crontab entry string
        """
        cron_entry = (
            f"{minute} {hour} * * * "
            f"/usr/bin/{self.sec_inspect_cmd} --mode {mode} "
            f"--output-dir {self.output_dir} >> {self.output_dir}/cron.log 2>&1"
        )
        return f"{self.cron_entry_comment}\n{cron_entry}"

    def generate_whitelist_crontab(self, day_of_week: int = 0, hour: int = 3,
                                     minute: int = 0, update_days: int = 30) -> str:
        """
        Generate crontab entry for whitelist auto-update
        
        Args:
            day_of_week: Day of week (0=Monday, 6=Sunday)
            hour: Hour to run (0-23)
            minute: Minute to run (0-59)
            update_days: Update interval in days
        
        Returns:
            Crontab entry string
        """
        cron_entry = (
            f"{minute} {hour} * * {day_of_week} "
            f"/usr/bin/{self.sec_inspect_cmd} --update-whitelist "
            f"--whitelist-limit 1000 >> {self.output_dir}/whitelist-cron.log 2>&1"
        )
        return f"{self.cron_entry_whitelist_comment}\n{cron_entry}"
    
    def get_current_crontab(self) -> str:
        """Get current user's crontab content"""
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return ""
    
    def install_crontab(self, mode: str = "daily", hour: int = 2,
                       minute: int = 0) -> bool:
        """
        Install sec-userspace crontab entry
        
        Args:
            mode: Scan mode
            hour: Hour to run
            minute: Minute to run
        
        Returns:
            True if successful
        """
        try:
            # Get existing crontab
            current = self.get_current_crontab()
            
            # Remove old sec-userspace entries if exist
            lines = current.split('\n')
            new_lines = []
            skip_next = False
            for line in lines:
                if line.strip() == self.cron_entry_comment:
                    skip_next = True
                    continue
                if skip_next and 'sec-userspace' in line:
                    skip_next = False
                    continue
                new_lines.append(line)
            
            # Add new entry
            new_entry = self.generate_crontab(mode, hour, minute)
            new_content = '\n'.join(new_lines).strip() + '\n\n' + new_entry
            
            # Install via stdin
            with subprocess.Popen(
                ["crontab", "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            ) as process:
                stdout, stderr = process.communicate(input=new_content, timeout=30)

                if process.returncode == 0:
                    logger.info(f"Crontab installed: sec-userspace {mode} scan at {hour:02d}:{minute:02d}")
                    return True
                else:
                    logger.error(f"Failed to install crontab: {stderr}")
                    return False

        except (subprocess.SubprocessError, OSError) as e:
            logger.error(f"Crontab installation failed: {e}")
            return False

    def remove_crontab(self) -> bool:
        """Remove sec-userspace crontab entry"""
        try:
            current = self.get_current_crontab()

            lines = current.split('\n')
            new_lines = []
            skip_next = False
            for line in lines:
                if line.strip() == self.cron_entry_comment:
                    skip_next = True
                    continue
                if skip_next and 'sec-userspace' in line:
                    skip_next = False
                    continue
                new_lines.append(line)

            new_content = '\n'.join(new_lines).strip()

            if new_content:
                with subprocess.Popen(
                    ["crontab", "-"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                ) as process:
                    stdout, stderr = process.communicate(input=new_content, timeout=30)
            else:
                subprocess.run(["crontab", "-r"], check=False, timeout=30)

            logger.info("Crontab removed: sec-userspace scheduled scan")
            return True

        except (subprocess.SubprocessError, OSError) as e:
            logger.error(f"Crontab removal failed: {e}")
            return False
    
    def check_crontab_status(self) -> Dict:
        """
        Check crontab status
        
        Returns:
            Dict with status information
        """
        result = {
            "installed": False,
            "entry": None,
            "next_run": None,
        }
        
        try:
            current = self.get_current_crontab()
            
            # Check if sec-userspace entry exists
            lines = current.split('\n')
            for i, line in enumerate(lines):
                if line.strip() == self.cron_entry_comment:
                    if i + 1 < len(lines) and 'sec-userspace' in lines[i + 1]:
                        result["installed"] = True
                        result["entry"] = lines[i + 1]
                        
                        # Parse cron schedule (simplified)
                        parts = lines[i + 1].split()
                        if len(parts) >= 5:
                            minute, hour = parts[0], parts[1]
                            result["next_run"] = f"Daily at {hour}:{minute}"
                        break
            
        except (OSError, ValueError, IndexError) as e:
            logger.debug(f"Failed to check crontab status: {e}")
        
        return result

    def install_whitelist_crontab(self, day_of_week: int = 0, hour: int = 3,
                                     minute: int = 0) -> bool:
        """
        Install whitelist update crontab entry
        
        Args:
            day_of_week: Day of week (0=Monday, 6=Sunday)
            hour: Hour to run
            minute: Minute to run
        
        Returns:
            True if successful
        """
        try:
            current = self.get_current_crontab()
            
            # Remove old whitelist entries if exist
            lines = current.split('\n')
            new_lines = []
            skip_next = False
            for line in lines:
                if line.strip() == self.cron_entry_whitelist_comment:
                    skip_next = True
                    continue
                if skip_next and '--update-whitelist' in line:
                    skip_next = False
                    continue
                new_lines.append(line)
            
            # Add new entry
            new_entry = self.generate_whitelist_crontab(day_of_week, hour, minute)
            new_content = '\n'.join(new_lines).strip() + '\n\n' + new_entry
            
            with subprocess.Popen(
                ["crontab", "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            ) as process:
                stdout, stderr = process.communicate(input=new_content, timeout=30)

                if process.returncode == 0:
                    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
                    day_name = day_names[day_of_week] if 0 <= day_of_week <= 6 else f"Day {day_of_week}"
                    logger.info(f"Whitelist crontab installed: weekly update on {day_name} at {hour:02d}:{minute:02d}")
                    return True
                else:
                    logger.error(f"Failed to install whitelist crontab: {stderr}")
                    return False

        except (subprocess.SubprocessError, OSError) as e:
            logger.error(f"Whitelist crontab installation failed: {e}")
            return False

    def remove_whitelist_crontab(self) -> bool:
        """Remove whitelist update crontab entry"""
        try:
            current = self.get_current_crontab()

            lines = current.split('\n')
            new_lines = []
            skip_next = False
            for line in lines:
                if line.strip() == self.cron_entry_whitelist_comment:
                    skip_next = True
                    continue
                if skip_next and '--update-whitelist' in line:
                    skip_next = False
                    continue
                new_lines.append(line)

            new_content = '\n'.join(new_lines).strip()

            if new_content:
                with subprocess.Popen(
                    ["crontab", "-"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                ) as process:
                    stdout, stderr = process.communicate(input=new_content, timeout=30)
            else:
                subprocess.run(["crontab", "-r"], check=False, timeout=30)

            logger.info("Whitelist crontab removed")
            return True

        except (subprocess.SubprocessError, OSError) as e:
            logger.error(f"Whitelist crontab removal failed: {e}")
            return False

    def check_whitelist_crontab_status(self) -> Dict:
        """
        Check whitelist crontab status
        
        Returns:
            Dict with status information
        """
        result = {
            "installed": False,
            "entry": None,
            "next_run": None,
        }
        
        try:
            current = self.get_current_crontab()
            lines = current.split('\n')
            for i, line in enumerate(lines):
                if line.strip() == self.cron_entry_whitelist_comment:
                    if i + 1 < len(lines) and '--update-whitelist' in lines[i + 1]:
                        result["installed"] = True
                        result["entry"] = lines[i + 1]
                        
                        parts = lines[i + 1].split()
                        if len(parts) >= 5:
                            minute, hour, dow = parts[0], parts[1], parts[4]
                            result["next_run"] = f"Weekly on {dow} at {hour}:{minute}"
                        break
            
        except (OSError, ValueError, IndexError) as e:
            logger.debug(f"Failed to check whitelist crontab status: {e}")
        
        return result
