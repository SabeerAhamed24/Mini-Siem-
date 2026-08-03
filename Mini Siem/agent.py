import socket
import json
import time
import os
import hashlib
import platform
import subprocess
import psutil

SERVER_IP = "192.168.16.37"
PORT = 9999
WATCH_DIR = r"C:\Users\sabee\OneDrive\Desktop\project new\watched"

baseline = {}
known_processes = set()

# Anomaly baseline
baseline_proc_count = None

# -------------------- USB STATE --------------------
known_usb = set()
usb_prompt_cooldown = {}
pending_usb = {}

COOLDOWN_SECONDS = 20
REQUIRED_CONSECUTIVE_SEEN = 2


def send_log(message, typ):
    log = {
        "source": socket.gethostname(),
        "type": typ,
        "message": message,
        "os": platform.system()
    }
    s = socket.socket()
    s.connect((SERVER_IP, PORT))
    s.send(json.dumps(log).encode())
    s.close()


# -------------------- FIM --------------------
def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def check_files():
    """
    Detect:
    - file modified
    - file renamed
    - file deleted
    - new file created
    """
    logs = []

    current_files = {}
    current_hash_to_path = {}

    # Scan current files
    for root, _, files in os.walk(WATCH_DIR):
        for file in files:
            path = os.path.join(root, file)
            try:
                file_hash = hash_file(path)
            except Exception:
                continue

            current_files[path] = file_hash
            current_hash_to_path[file_hash] = path

    old_paths = set(baseline.keys())
    current_paths = set(current_files.keys())

    # 1) Detect modified files
    for path in old_paths & current_paths:
        if baseline[path] != current_files[path]:
            logs.append(f"File modified: {path}")

    # 2) Detect removed / renamed files
    removed_paths = old_paths - current_paths
    added_paths = set(current_paths - old_paths)

    for old_path in removed_paths:
        old_hash = baseline[old_path]

        # Same hash at new path => renamed
        if old_hash in current_hash_to_path:
            new_path = current_hash_to_path[old_hash]
            if new_path in added_paths:
                logs.append(f"File renamed: {old_path} -> {new_path}")
                added_paths.discard(new_path)
            else:
                logs.append(f"File deleted: {old_path}")
        else:
            logs.append(f"File deleted: {old_path}")

    # 3) Detect new files
    for new_path in added_paths:
        logs.append(f"New file detected: {new_path}")

    # Update baseline
    baseline.clear()
    baseline.update(current_files)

    return logs


# -------------------- PROCESS MONITOR --------------------
def check_processes():
    logs = []
    for p in psutil.process_iter(['name']):
        name = (p.info.get('name') or "").strip()
        if not name:
            continue
        if name not in known_processes:
            known_processes.add(name)
            logs.append(f"New process detected: {name}")
    return logs


# -------------------- ANOMALY (Process spike) --------------------
def check_process_anomaly(threshold_jump=25):
    global baseline_proc_count
    try:
        current = len(psutil.pids())
        if baseline_proc_count is None:
            baseline_proc_count = current
            return None

        jump = current - baseline_proc_count

        # Slowly adapt baseline
        baseline_proc_count = int((baseline_proc_count * 0.9) + (current * 0.1))

        if jump >= threshold_jump:
            return f"Anomaly: Process spike detected (jump={jump}, current={current})"
    except Exception:
        return None
    return None


# -------------------- USB HELPERS --------------------
def list_removable_drives_windows():
    """
    Returns removable drives like ['E:', 'F:']
    """
    drives = []
    try:
        out = subprocess.check_output(
            ["wmic", "logicaldisk", "where", "drivetype=2", "get", "deviceid"],
            text=True,
            stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            line = line.strip()
            if line.endswith(":"):
                drives.append(line)
    except Exception:
        pass
    return drives


def list_removable_drives_linux():
    mounts = []
    for base in ["/media", "/run/media"]:
        if os.path.isdir(base):
            for root, dirs, _ in os.walk(base):
                for d in dirs:
                    mounts.append(os.path.join(root, d))
                break
    return mounts


def ask_allow_popup(title, text):
    """
    Returns True if allowed, False if blocked.
    """
    if platform.system() == "Windows":
        try:
            import ctypes
            MB_YESNO = 0x04
            ICON_QUESTION = 0x20
            result = ctypes.windll.user32.MessageBoxW(0, text, title, MB_YESNO | ICON_QUESTION)
            return result == 6  # YES=6, NO=7
        except Exception:
            pass

    try:
        ans = input(f"{title}\n{text}\nAllow? (y/n): ").strip().lower()
        return ans == "y"
    except Exception:
        return True


def soft_block_windows(drive_letter):
    """
    Dismount the USB volume so it disappears from File Explorer.
    Often requires running Python as Administrator.
    """
    try:
        target = drive_letter + "\\"
        r = subprocess.run(
            ["mountvol", target, "/p"],
            capture_output=True,
            text=True
        )
        return r.returncode == 0
    except Exception:
        return False


def soft_block_linux(mount_point):
    try:
        subprocess.run(["umount", mount_point], capture_output=True, text=True)
        return True
    except Exception:
        return False


def scan_usb_for_threats(drive_letter):
    """
    Lightweight rule-based USB scan after allowing the USB.
    """
    findings = []

    suspicious_exts = {".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".scr", ".dll"}
    suspicious_names = {"autorun.inf", "runme.exe", "setup.bat", "payload.exe"}

    try:
        root_path = drive_letter + "\\"

        for root, dirs, files in os.walk(root_path):
            for file in files:
                file_lower = file.lower()
                full_path = os.path.join(root, file)

                # Suspicious names
                if file_lower in suspicious_names:
                    findings.append(f"Suspicious file name detected: {full_path}")

                # Suspicious extensions
                _, ext = os.path.splitext(file_lower)
                if ext in suspicious_exts:
                    findings.append(f"Suspicious executable/script file detected: {full_path}")

                # Hidden file check
                try:
                    attrs = os.stat(full_path).st_file_attributes
                    if attrs & 2:  # FILE_ATTRIBUTE_HIDDEN
                        findings.append(f"Hidden file detected: {full_path}")
                except Exception:
                    pass

    except Exception as e:
        findings.append(f"USB scan failed: {drive_letter} | {e}")

    return findings


# -------------------- USB DETECTION --------------------
def check_usb_events():
    """
    Stable detection:
    - drive must appear twice before prompting
    - cooldown prevents popup spam
    - reinsertion prompts again after removal
    - allow => scan USB
    - block => dismount USB
    """
    global known_usb
    events = []
    now = time.time()

    sysname = platform.system()

    if sysname == "Windows":
        current = set(list_removable_drives_windows())

        # Handle removals so reinsertion works again
        removed = known_usb - current
        if removed:
            for d in removed:
                pending_usb.pop(d, None)
                usb_prompt_cooldown.pop(d, None)
            known_usb = known_usb - removed

        # Newly seen candidates
        new_candidates = current - known_usb

        for d in sorted(new_candidates):
            pending_usb[d] = pending_usb.get(d, 0) + 1

            # Require stable appearance
            if pending_usb[d] < REQUIRED_CONSECUTIVE_SEEN:
                continue

            pending_usb.pop(d, None)

            # Cooldown check
            last = usb_prompt_cooldown.get(d, 0)
            if (now - last) < COOLDOWN_SECONDS:
                continue
            usb_prompt_cooldown[d] = now

            events.append(("USB_INSERT", f"USB detected: {d}"))

            allow = ask_allow_popup(
                "USB Device Detected",
                f"Removable drive {d} inserted.\nDo you want to ALLOW it?"
            )

            if allow:
                events.append(("USB_ALLOWED", f"USB allowed by user: {d}"))
                known_usb.add(d)

                findings = scan_usb_for_threats(d)
                if findings:
                    for finding in findings:
                        events.append(("USB_SCAN", finding))
                else:
                    events.append(("USB_SCAN", f"No obvious threats found on USB: {d}"))

            else:
                ok = soft_block_windows(d)
                events.append(("USB_BLOCKED", f"USB blocked by user: {d}. Dismount attempted={ok}"))
                known_usb.add(d)

                # If successfully blocked, allow future reinsertion detection
                if ok:
                    known_usb.discard(d)

    else:
        current = set(list_removable_drives_linux())

        removed = known_usb - current
        if removed:
            for mp in removed:
                pending_usb.pop(mp, None)
                usb_prompt_cooldown.pop(mp, None)
            known_usb = known_usb - removed

        new_candidates = current - known_usb

        for mp in sorted(new_candidates):
            pending_usb[mp] = pending_usb.get(mp, 0) + 1

            if pending_usb[mp] < REQUIRED_CONSECUTIVE_SEEN:
                continue

            pending_usb.pop(mp, None)

            last = usb_prompt_cooldown.get(mp, 0)
            if (now - last) < COOLDOWN_SECONDS:
                continue
            usb_prompt_cooldown[mp] = now

            events.append(("USB_INSERT", f"USB detected (mount): {mp}"))

            allow = ask_allow_popup(
                "USB Device Detected",
                f"Removable media mounted at {mp}.\nDo you want to ALLOW it?"
            )

            if allow:
                events.append(("USB_ALLOWED", f"USB allowed by user: {mp}"))
                known_usb.add(mp)
            else:
                ok = soft_block_linux(mp)
                events.append(("USB_BLOCKED", f"USB blocked by user: {mp}. Unmount attempted={ok}"))
                known_usb.add(mp)
                if ok:
                    known_usb.discard(mp)

    return events


# -------------------- HEARTBEAT --------------------
def send_heartbeat():
    send_log("Agent heartbeat", "HEARTBEAT")


print("[Agent] Monitoring started...")

heartbeat_counter = 0

while True:
    if not os.path.exists(WATCH_DIR):
        os.makedirs(WATCH_DIR)

    # File Integrity Monitoring
    for f in check_files():
        send_log(f, "FIM")

    # Process Monitoring
    for p in check_processes():
        send_log(p, "PROCESS")

    # USB Detection / Allow / Block / Scan
    for typ, msg in check_usb_events():
        send_log(msg, typ)

    # Anomaly Detection
    anomaly = check_process_anomaly(threshold_jump=25)
    if anomaly:
        send_log(anomaly, "ANOMALY")

    # Heartbeat every ~10 seconds
    heartbeat_counter += 1
    if heartbeat_counter >= 2:
        send_heartbeat()
        heartbeat_counter = 0

    time.sleep(5)
