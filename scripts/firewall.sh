#!/bin/bash
# WireMCP-rs Firewall Script
# Auto-reverts after 5 minutes if not confirmed
# Usage: sudo bash firewall.sh [apply|confirm|revert|status]

set -e

BACKUP="/tmp/iptables-backup-$(date +%s).rules"
CONFIRM_FILE="/tmp/firewall-confirmed"

apply_rules() {
    echo "[*] Saving current iptables rules to $BACKUP"
    iptables-save > "$BACKUP"

    echo "[*] Applying firewall rules..."

    # Flush INPUT chain (keep FORWARD/DOCKER intact)
    iptables -F INPUT

    # 1. Allow loopback
    iptables -A INPUT -i lo -j ACCEPT

    # 2. Allow established/related connections (keeps current SSH alive)
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # 3. SSH with rate limiting (max 5 new connections per minute per IP)
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 6 --name SSH -j DROP
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

    # 4. HTTPS (443)
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT

    # 5. WireGuard VPN (51820/udp)
    iptables -A INPUT -p udp --dport 51820 -j ACCEPT

    # 6. Allow traffic from WireGuard tunnel
    iptables -A INPUT -i wg0 -j ACCEPT

    # 7. Docker internal networks
    iptables -A INPUT -i docker0 -j ACCEPT
    iptables -A INPUT -i br-d6e71e5f62c3 -j ACCEPT

    # 8. DHCP client (needed for cloud instances)
    iptables -A INPUT -p udp --sport 67 --dport 68 -j ACCEPT

    # 9. ICMP (ping) with rate limit - 5/sec
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/sec --limit-burst 10 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT

    # 10. Block LLMNR (5355) explicitly + log
    iptables -A INPUT -p tcp --dport 5355 -j DROP
    iptables -A INPUT -p udp --dport 5355 -j DROP

    # 11. Block DNS from outside (anti-amplification)
    iptables -A INPUT -p udp --dport 53 -j DROP
    iptables -A INPUT -p tcp --dport 53 -j DROP

    # 12. Log + drop everything else
    iptables -A INPUT -m limit --limit 3/min -j LOG --log-prefix "IPT_DROP: " --log-level 4
    iptables -A INPUT -j DROP

    # Set default policy
    iptables -P INPUT DROP

    echo "[+] Rules applied!"
    echo ""
    echo "============================================"
    echo "  IMPORTANT: Auto-revert in 5 minutes!"
    echo "  Run: sudo bash $0 confirm"
    echo "  to make rules permanent."
    echo "============================================"
    echo ""

    # Schedule auto-revert
    rm -f "$CONFIRM_FILE"
    (
        sleep 300
        if [ ! -f "$CONFIRM_FILE" ]; then
            echo "[!] No confirmation received. Reverting firewall rules..."
            iptables-restore < "$BACKUP"
            echo "[+] Rules reverted to previous state."
        fi
    ) &
    echo $! > /tmp/firewall-revert-pid
    echo "[*] Auto-revert PID: $(cat /tmp/firewall-revert-pid)"
}

confirm_rules() {
    touch "$CONFIRM_FILE"
    if [ -f /tmp/firewall-revert-pid ]; then
        kill "$(cat /tmp/firewall-revert-pid)" 2>/dev/null || true
        rm -f /tmp/firewall-revert-pid
    fi
    echo "[+] Firewall rules confirmed and permanent!"
    echo "[*] Backup saved at: $(ls -t /tmp/iptables-backup-*.rules 2>/dev/null | head -1)"
}

revert_rules() {
    LATEST=$(ls -t /tmp/iptables-backup-*.rules 2>/dev/null | head -1)
    if [ -z "$LATEST" ]; then
        echo "[!] No backup found. Flushing INPUT and setting ACCEPT policy."
        iptables -F INPUT
        iptables -P INPUT ACCEPT
    else
        echo "[*] Reverting to: $LATEST"
        iptables-restore < "$LATEST"
    fi
    echo "[+] Rules reverted."
}

show_status() {
    echo "=== INPUT Chain ==="
    iptables -L INPUT -n -v --line-numbers
    echo ""
    echo "=== Policy ==="
    iptables -L INPUT | head -1
}

case "${1:-status}" in
    apply)   apply_rules ;;
    confirm) confirm_rules ;;
    revert)  revert_rules ;;
    status)  show_status ;;
    *) echo "Usage: $0 [apply|confirm|revert|status]" ;;
esac
