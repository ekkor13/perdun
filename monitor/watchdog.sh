#!/bin/bash
#
# perdun/monitor/watchdog.sh
# monitors VirtualBox VM process directly (no VBoxManage needed)
#
# usage: ./watchdog.sh "win11_25H2"
#        ./watchdog.sh "win11_25H2" 10    — check every 10 sec

VM_NAME="${1:?usage: watchdog.sh <vm_name>}"
INTERVAL="${2:-5}"

echo "[*] perdun watchdog"
echo "[*] monitoring VM: $VM_NAME"
echo "[*] check interval: ${INTERVAL}s"

# find the VM process
VM_PID=$(pgrep -f "VirtualBoxVM.*--comment ${VM_NAME}")

if [ -z "$VM_PID" ]; then
    echo "[!] VM process not found. Running VMs:"
    ps aux | grep VirtualBoxVM | grep -v grep
    exit 1
fi

echo "[+] VM PID: $VM_PID"
echo "[*] watching... press Ctrl+C to stop"
echo ""

START_TIME=$(date +%s)

notify() {
    local title="$1"
    local body="$2"

    # desktop notification
    if command -v notify-send &>/dev/null; then
        notify-send -u critical "$title" "$body"
    fi

    # terminal bell + flash
    echo -e "\a\a\a"

    echo ""
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "  $title"
    echo "  $body"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ""
}

while true; do
    if ! kill -0 "$VM_PID" 2>/dev/null; then
        ELAPSED=$(( $(date +%s) - START_TIME ))
        notify "PERDUN: VM DIED" \
               "VM '$VM_NAME' (PID $VM_PID) gone after ${ELAPSED}s. Check C:\\Windows\\Minidump and C:\\perdun_logs"

        # wait for VM to come back (reboot after BSOD)
        echo "[*] waiting for VM to restart..."
        while true; do
            sleep 5
            NEW_PID=$(pgrep -f "VirtualBoxVM.*--comment ${VM_NAME}")
            if [ -n "$NEW_PID" ]; then
                VM_PID="$NEW_PID"
                echo "[+] VM is back! new PID: $VM_PID"
                START_TIME=$(date +%s)
                break
            fi
        done
    fi

    sleep "$INTERVAL"
done
