import json
from pathlib import Path
from datetime import datetime
from .color import UI
class Logger:
    AUDIT_FILENAME = "log.log"
    def __init__(self, vault_dir: str = "save"):
        self.dir = Path(vault_dir)
        self.log_file = self.dir / self.AUDIT_FILENAME
        self.dir.mkdir(parents=True, exist_ok=True)
    def log(self, action: str, service: str = None, status: str = "Success", 
            reason: str = None, username: str = None):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "service": service,
            "username": username,
            "status": status,
            "reason": reason
        }
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            UI.err(f"Failed to write audit log: {e}")
    def get_logs(self) -> list:
        if not self.log_file.exists():
            return []
        logs = []
        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    if line.strip():
                        try:
                            logs.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            UI.err(f"Failed to read audit logs: {e}")
        return logs
    def display_logs(self, limit: int = 20):
        logs = self.get_logs()
        
        if not logs:
            UI.info("📭 No audit logs")
            return
        recent_logs = logs[-limit:]
        print("\n" + "="*130)
        print(f"{'Timestamp':<21} | {'Action':<10} | {'Service':<20} | {'Username':<15} | {'Status':<10} | {'Reason':<40}")
        print("="*130)
        for log in recent_logs:
            timestamp = log['timestamp'][:19]  # YYYY-MM-DD HH:MM:SS
            action = log['action'][:10]
            service = (log['service'] or "N/A")[:20]
            username = (log['username'] or "N/A")[:15]
            status = log['status'][:10]
            reason = (log['reason'] or "")[:40]
            # Color code status
            if status == "Success":
                print(f"{timestamp} | {action:<10} | {service:<20} | {username:<15} | ✓ {status:<8} | {reason:<40}")
            else:
                print(f"{timestamp} | {action:<10} | {service:<20} | {username:<15} | ✗ {status:<8} | {reason:<40}")
        print("="*130)
        print(f"Total logs displayed: {len(recent_logs)} (out of {len(logs)} total)\n")
    def get_logs_by_service(self, service: str) -> list:
        logs = self.get_logs()
        return [log for log in logs if log['service'] and log['service'].lower() == service.lower()]
    def get_failed_attempts(self) -> list:
        logs = self.get_logs()
        return [log for log in logs if log['status'] == 'Failed']
    def get_logs_by_action(self, action: str) -> list:
        logs = self.get_logs()
        return [log for log in logs if log['action'].lower() == action.lower()]
    
    def clear_logs(self):
        try:
            if self.log_file.exists():
                self.log_file.unlink()
                UI.ok("✓ Audit logs cleared")
        except Exception as e:
            UI.err(f"Failed to clear audit logs: {e}")
    def display_statistics(self):
        logs = self.get_logs()
        if not logs:
            UI.info("📭 No audit logs")
            return
        total_logs = len(logs)
        successful_actions = len([l for l in logs if l['status'] == 'Success'])
        failed_actions = len([l for l in logs if l['status'] == 'Failed'])
        action_counts = {}
        for log in logs:
            action = log['action']
            action_counts[action] = action_counts.get(action, 0) + 1
        service_counts = {}
        for log in logs:
            if log['service']:
                service = log['service']
                service_counts[service] = service_counts.get(service, 0) + 1
        print("\n" + "="*60)
        print("AUDIT LOG STATISTICS")
        print("="*60)
        print(f"Total Actions: {total_logs}")
        print(f"Successful: {successful_actions} ✓")
        print(f"Failed: {failed_actions} ✗")
        print(f"Success Rate: {(successful_actions/total_logs*100):.1f}%")
        print("\n--- Actions Breakdown ---")
        for action, count in sorted(action_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {action:<15} : {count:>3}")
        
        if service_counts:
            print("\n--- Most Accessed Services ---")
            for service, count in sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {service:<20} : {count:>3}")
        print("="*60 + "\n")