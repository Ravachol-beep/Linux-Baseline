#!/usr/bin/env bash
# =============================================================================
#  CIS Linux Security Baseline Tool  v1.0
#  Audit & remediation script aligned with CIS Benchmarks (Level 1 & Level 2)
#  Supports: Ubuntu, Debian, RHEL/CentOS/Rocky/AlmaLinux, Fedora
#
#  Usage:
#    sudo ./cis-baseline.sh                  # Interactive audit + optional fix
#    sudo ./cis-baseline.sh --audit-only     # Audit only, no prompts to fix
#    sudo ./cis-baseline.sh --level 1        # Only run Level 1 checks
#    sudo ./cis-baseline.sh --level 2        # Run Level 1 + Level 2 checks
#    sudo ./cis-baseline.sh --section 1      # Run only section 1 checks
#    sudo ./cis-baseline.sh --report /tmp/r  # Save HTML report to path
#    sudo ./cis-baseline.sh --help
# =============================================================================

set -uo pipefail

# ── Globals ──────────────────────────────────────────────────────────────────
TOOL_VERSION="1.0"
AUDIT_ONLY=false
LEVEL=1
SECTION_FILTER=""
REPORT_FILE=""
LOG_FILE="/var/log/cis-baseline-$(date +%Y%m%d-%H%M%S).log"

PASS=0; FAIL=0; WARN=0; SKIP=0
declare -a RESULTS=()

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
detect_os() {
    if   [[ -f /etc/os-release ]]; then source /etc/os-release; OS_ID="${ID,,}"; OS_VER="${VERSION_ID:-0}"
    elif [[ -f /etc/redhat-release ]]; then OS_ID="rhel"; OS_VER=$(grep -oP '\d+' /etc/redhat-release | head -1)
    else OS_ID="unknown"; OS_VER="0"; fi
    case "$OS_ID" in
        ubuntu|debian)            OS_FAMILY="debian" ;;
        rhel|centos|rocky|almalinux|fedora|ol) OS_FAMILY="rhel" ;;
        *)                        OS_FAMILY="unknown" ;;
    esac
}

log() { echo "[$(date '+%Y-%m-%dT%H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null || true; }

print_banner() {
    echo -e "${BOLD}${CYAN}"
    cat <<'EOF'
   _____ _____  _____   ____                  _ _
  / ____|_   _|/ ____| |  _ \                | (_)
 | |      | | | (___   | |_) | __ _ ___  ___| |_ _ __   ___
 | |      | |  \___ \  |  _ < / _` / __|/ _ \ | | '_ \ / _ \
 | |____ _| |_ ____) | | |_) | (_| \__ \  __/ | | | | |  __/
  \_____|_____|_____/  |____/ \__,_|___/\___|_|_|_| |_|\___|

  Linux CIS Security Baseline Tool  ·  v1.0
  Aligned with CIS Benchmarks (Level 1 & 2)
EOF
    echo -e "${RESET}"
}

section_header() {
    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN}  Section $1: $2${RESET}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${RESET}"
}

# record_result <id> <level> <description> <status> [detail]
record_result() {
    local id="$1" lvl="$2" desc="$3" status="$4" detail="${5:-}"
    local icon color
    case "$status" in
        PASS) icon="✔"; color="$GREEN"; ((PASS++)) ;;
        FAIL) icon="✘"; color="$RED";  ((FAIL++)) ;;
        WARN) icon="⚠"; color="$YELLOW"; ((WARN++)) ;;
        SKIP) icon="○"; color="$CYAN";  ((SKIP++)) ;;
    esac
    printf "  ${color}[${icon}]${RESET} ${BOLD}%-8s${RESET} [L%s] %s\n" "$id" "$lvl" "$desc"
    [[ -n "$detail" ]] && echo -e "         ${YELLOW}↳ $detail${RESET}"
    RESULTS+=("$id|$lvl|$desc|$status|$detail")
    log "$status [$id] L$lvl $desc ${detail:+| $detail}"
}

# prompt_fix <id> <description> <fix_command...>
# Returns 0 if user said yes and fix succeeded, 1 otherwise
prompt_fix() {
    local id="$1" desc="$2"; shift 2
    $AUDIT_ONLY && return 1
    echo ""
    echo -e "  ${YELLOW}╔══ Remediation Available ══════════════════════════════╗${RESET}"
    echo -e "  ${YELLOW}║${RESET}  ID: $id — $desc"
    echo -e "  ${YELLOW}║${RESET}  Fix: $*"
    echo -e "  ${YELLOW}╚═══════════════════════════════════════════════════════╝${RESET}"
    read -r -p "  Apply this fix? [y/N] " ans
    if [[ "${ans,,}" == "y" ]]; then
        if eval "$@" >> "$LOG_FILE" 2>&1; then
            echo -e "  ${GREEN}✔ Fix applied successfully.${RESET}"
            return 0
        else
            echo -e "  ${RED}✘ Fix failed — check $LOG_FILE for details.${RESET}"
            return 1
        fi
    fi
    return 1
}

should_run_section() {
    [[ -z "$SECTION_FILTER" ]] && return 0
    [[ "$1" == "$SECTION_FILTER"* ]] && return 0
    return 1
}

# ── SECTION 1: Initial Setup / Filesystem ────────────────────────────────────
section_1() {
    section_header "1" "Initial Setup — Filesystem & Software"

    # 1.1.1  Disable unused filesystems
    local disabled_fs=(cramfs freevxfs jffs2 hfs hfsplus squashfs udf)
    for fs in "${disabled_fs[@]}"; do
        local res
        res=$(modprobe -n -v "$fs" 2>&1)
        if echo "$res" | grep -q "install /bin/true\|install /bin/false"; then
            record_result "1.1.1.$fs" 1 "Filesystem $fs disabled" PASS
        else
            record_result "1.1.1.$fs" 1 "Filesystem $fs disabled" FAIL \
                "Not blacklisted. echo 'install $fs /bin/true' >> /etc/modprobe.d/CIS.conf"
            prompt_fix "1.1.1.$fs" "Disable $fs filesystem" \
                "echo 'install $fs /bin/true' >> /etc/modprobe.d/CIS.conf && echo 'blacklist $fs' >> /etc/modprobe.d/CIS.conf"
        fi
    done

    # 1.1.2  /tmp separate partition
    if findmnt /tmp &>/dev/null; then
        record_result "1.1.2" 1 "/tmp is a separate partition" PASS
    else
        record_result "1.1.2" 1 "/tmp is a separate partition" WARN \
            "/tmp is not a separate mount point (manual partition change needed)"
    fi

    # 1.1.3-5  /tmp mount options
    for opt in nodev nosuid noexec; do
        if findmnt /tmp 2>/dev/null | grep -q "$opt"; then
            record_result "1.1.3-5.$opt" 1 "/tmp has $opt option" PASS
        else
            record_result "1.1.3-5.$opt" 1 "/tmp has $opt option" FAIL \
                "Add $opt to /tmp mount options in /etc/fstab or systemd tmp.mount"
        fi
    done

    # 1.1.6  Separate /var partition
    if findmnt /var &>/dev/null; then
        record_result "1.1.6" 2 "/var is a separate partition" PASS
    else
        record_result "1.1.6" 2 "/var is a separate partition" WARN \
            "Separate /var partition recommended for Level 2 (requires disk re-partitioning)"
    fi

    # 1.1.7  /var/tmp nodev/nosuid/noexec
    for opt in nodev nosuid noexec; do
        if findmnt /var/tmp 2>/dev/null | grep -q "$opt"; then
            record_result "1.1.7.$opt" 1 "/var/tmp has $opt" PASS
        else
            record_result "1.1.7.$opt" 1 "/var/tmp has $opt" FAIL \
                "Add $opt to /var/tmp in /etc/fstab"
        fi
    done

    # 1.1.8  /dev/shm nodev/nosuid/noexec
    for opt in nodev nosuid noexec; do
        if findmnt /dev/shm 2>/dev/null | grep -q "$opt"; then
            record_result "1.1.8.$opt" 1 "/dev/shm has $opt" PASS
        else
            record_result "1.1.8.$opt" 1 "/dev/shm has $opt" FAIL \
                "Add tmpfs /dev/shm tmpfs defaults,$opt 0 0 to /etc/fstab"
            prompt_fix "1.1.8.$opt" "/dev/shm $opt" \
                "mount -o remount,$opt /dev/shm && echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab"
        fi
    done

    # 1.1.9  Disable USB storage
    local usb_res
    usb_res=$(modprobe -n -v usb-storage 2>&1)
    if echo "$usb_res" | grep -q "install /bin/true\|install /bin/false"; then
        record_result "1.1.9" 1 "USB storage disabled" PASS
    else
        record_result "1.1.9" 1 "USB storage disabled" FAIL \
            "echo 'install usb-storage /bin/true' >> /etc/modprobe.d/CIS.conf"
        prompt_fix "1.1.9" "Disable USB storage" \
            "echo 'install usb-storage /bin/true' >> /etc/modprobe.d/CIS.conf && echo 'blacklist usb-storage' >> /etc/modprobe.d/CIS.conf"
    fi

    # 1.2  Software updates / GPG
    section_header "1.2" "Software Updates"
    if [[ "$OS_FAMILY" == "debian" ]]; then
        if apt-get -s upgrade 2>/dev/null | grep -q "^0 upgraded"; then
            record_result "1.2.1" 1 "System packages up to date" PASS
        else
            record_result "1.2.1" 1 "System packages up to date" WARN \
                "Pending updates found — run: apt-get upgrade"
        fi
    else
        if yum check-update --quiet &>/dev/null; then
            record_result "1.2.1" 1 "System packages up to date" PASS
        else
            record_result "1.2.1" 1 "System packages up to date" WARN \
                "Pending updates found — run: yum update"
        fi
    fi

    # 1.3  Filesystem integrity (AIDE)
    section_header "1.3" "Filesystem Integrity Checking"
    if command -v aide &>/dev/null || command -v aide2 &>/dev/null; then
        record_result "1.3.1" 1 "AIDE installed" PASS
    else
        record_result "1.3.1" 1 "AIDE installed" FAIL "Install AIDE: apt install aide / yum install aide"
        if [[ "$OS_FAMILY" == "debian" ]]; then
            prompt_fix "1.3.1" "Install AIDE" "apt-get install -y aide && aideinit"
        else
            prompt_fix "1.3.1" "Install AIDE" "yum install -y aide && aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
        fi
    fi

    if crontab -l -u root 2>/dev/null | grep -q "aide\|aide2" || \
       grep -rq "aide" /etc/cron.* /etc/crontab 2>/dev/null; then
        record_result "1.3.2" 1 "AIDE integrity check is scheduled" PASS
    else
        record_result "1.3.2" 1 "AIDE integrity check is scheduled" FAIL \
            "Add AIDE to cron: echo '0 5 * * * root aide --check' >> /etc/crontab"
        prompt_fix "1.3.2" "Schedule AIDE check" \
            "echo '0 5 * * * root aide --check' >> /etc/crontab"
    fi

    # 1.4  Secure Boot
    section_header "1.4" "Secure Boot Settings"
    if [[ -f /boot/grub/grub.cfg ]] || [[ -f /boot/grub2/grub.cfg ]]; then
        local grub_cfg
        grub_cfg=$(find /boot -name grub.cfg 2>/dev/null | head -1)
        local grub_perms
        grub_perms=$(stat -c "%a" "$grub_cfg" 2>/dev/null || echo "000")
        if [[ "$grub_perms" -le 600 ]]; then
            record_result "1.4.1" 1 "Bootloader config permissions ≤ 600" PASS
        else
            record_result "1.4.1" 1 "Bootloader config permissions ≤ 600" FAIL \
                "Current: $grub_perms — run: chmod og-rwx $grub_cfg"
            prompt_fix "1.4.1" "Restrict bootloader config" "chmod og-rwx $grub_cfg"
        fi
    else
        record_result "1.4.1" 1 "Bootloader config found" SKIP "grub.cfg not found at standard paths"
    fi

    # Check single-user auth
    if grep -q "sulogin\|rescue.service" /usr/lib/systemd/system/rescue.service 2>/dev/null || \
       grep -q "ExecStart.*-b\|sulogin" /lib/systemd/system/emergency.service 2>/dev/null; then
        record_result "1.4.3" 1 "Single-user mode requires authentication" PASS
    else
        record_result "1.4.3" 1 "Single-user mode requires authentication" WARN \
            "Verify /usr/lib/systemd/system/rescue.service uses sulogin"
    fi

    # 1.5  Process hardening
    section_header "1.5" "Additional Process Hardening"
    local core_dumps
    core_dumps=$(grep -r "hard core" /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null | grep -v "^#")
    if [[ -n "$core_dumps" ]]; then
        record_result "1.5.1" 1 "Core dumps restricted" PASS
    else
        record_result "1.5.1" 1 "Core dumps restricted" FAIL \
            "Add '* hard core 0' to /etc/security/limits.conf"
        prompt_fix "1.5.1" "Restrict core dumps" \
            "echo '* hard core 0' >> /etc/security/limits.conf && echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/60-cis.conf && sysctl -p /etc/sysctl.d/60-cis.conf"
    fi

    # ASLR
    local aslr
    aslr=$(sysctl kernel.randomize_va_space 2>/dev/null | awk '{print $3}')
    if [[ "$aslr" == "2" ]]; then
        record_result "1.5.3" 1 "ASLR enabled (kernel.randomize_va_space=2)" PASS
    else
        record_result "1.5.3" 1 "ASLR enabled (kernel.randomize_va_space=2)" FAIL \
            "Current value: ${aslr:-unset}"
        prompt_fix "1.5.3" "Enable ASLR" \
            "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/60-cis.conf && sysctl -w kernel.randomize_va_space=2"
    fi

    # 1.6  SELinux / AppArmor
    section_header "1.6" "Mandatory Access Control"
    if [[ "$OS_FAMILY" == "rhel" ]]; then
        local selinux_status
        selinux_status=$(getenforce 2>/dev/null || echo "Disabled")
        if [[ "$selinux_status" == "Enforcing" ]]; then
            record_result "1.6.1" 1 "SELinux is Enforcing" PASS
        elif [[ "$selinux_status" == "Permissive" ]]; then
            record_result "1.6.1" 1 "SELinux is Enforcing" WARN "SELinux is Permissive — set to Enforcing in /etc/selinux/config"
        else
            record_result "1.6.1" 1 "SELinux is Enforcing" FAIL \
                "SELinux is Disabled — set SELINUX=enforcing in /etc/selinux/config and reboot"
        fi
    else
        if command -v apparmor_status &>/dev/null && apparmor_status --enabled 2>/dev/null; then
            record_result "1.6.1" 1 "AppArmor enabled" PASS
        else
            record_result "1.6.1" 1 "AppArmor enabled" FAIL \
                "Install/enable AppArmor: apt install apparmor apparmor-utils && systemctl enable apparmor"
        fi
    fi
}

# ── SECTION 2: Services ───────────────────────────────────────────────────────
section_2() {
    section_header "2" "Services — Unnecessary Services Disabled"

    local unused_services=(
        xinetd openbsd-inetd inetutils-inetd
        avahi-daemon cups nfs-server rpcbind
        rsyncd slapd vsftpd dovecot smbd squid snmpd
        nis ypbind talk talkd telnet rsh
    )

    for svc in "${unused_services[@]}"; do
        # normalise: ubuntu uses .service suffix, rhel uses plain name
        local svc_name="${svc}.service"
        if systemctl list-unit-files "$svc_name" 2>/dev/null | grep -qE "enabled|running"; then
            record_result "2.x.$svc" 1 "Service $svc disabled/not installed" FAIL \
                "Disable unless required: systemctl disable --now $svc"
            prompt_fix "2.x.$svc" "Disable $svc" "systemctl disable --now $svc"
        else
            # also check if package is installed
            if [[ "$OS_FAMILY" == "debian" ]]; then
                dpkg -l "$svc" &>/dev/null && \
                    record_result "2.x.$svc" 1 "Package $svc removed" WARN "Installed but not enabled — consider removing" || \
                    record_result "2.x.$svc" 1 "Service $svc not present" PASS
            else
                record_result "2.x.$svc" 1 "Service $svc not present" PASS
            fi
        fi
    done

    # 2.2  Time synchronisation
    section_header "2.2" "Time Synchronisation"
    local time_active=false
    for tsvc in chronyd ntpd systemd-timesyncd; do
        systemctl is-active "$tsvc" &>/dev/null && time_active=true && break
    done
    if $time_active; then
        record_result "2.2.1" 1 "Time synchronisation service active" PASS
    else
        record_result "2.2.1" 1 "Time synchronisation service active" FAIL \
            "Install and enable chrony: apt/yum install chrony && systemctl enable --now chronyd"
        if [[ "$OS_FAMILY" == "debian" ]]; then
            prompt_fix "2.2.1" "Install chrony" "apt-get install -y chrony && systemctl enable --now chrony"
        else
            prompt_fix "2.2.1" "Install chrony" "yum install -y chrony && systemctl enable --now chronyd"
        fi
    fi

    # X11 display manager
    if systemctl is-active gdm3 gdm lightdm xdm kdm &>/dev/null; then
        record_result "2.3" 2 "X Window System (display manager) not running" WARN \
            "If this is a server, disable the display manager: systemctl disable --now gdm"
    else
        record_result "2.3" 1 "X Window System display manager not running" PASS
    fi
}

# ── SECTION 3: Network ────────────────────────────────────────────────────────
section_3() {
    section_header "3" "Network Configuration"

    # Helper: sysctl check + optional fix
    sysctl_check() {
        local id="$1" lvl="$2" param="$3" expected="$4" desc="$5"
        local actual
        actual=$(sysctl "$param" 2>/dev/null | awk '{print $3}')
        if [[ "$actual" == "$expected" ]]; then
            record_result "$id" "$lvl" "$desc" PASS
        else
            record_result "$id" "$lvl" "$desc" FAIL "Current: ${actual:-unset}, expected: $expected"
            prompt_fix "$id" "$desc" \
                "echo '$param = $expected' >> /etc/sysctl.d/60-cis.conf && sysctl -w $param=$expected"
        fi
    }

    sysctl_check "3.1.1" 1 "net.ipv4.ip_forward"              "0" "IP forwarding disabled"
    sysctl_check "3.1.2" 1 "net.ipv4.conf.all.send_redirects" "0" "Send redirects disabled"
    sysctl_check "3.2.1" 1 "net.ipv4.conf.all.accept_source_route" "0" "Source route acceptance disabled"
    sysctl_check "3.2.2" 1 "net.ipv4.conf.all.accept_redirects"    "0" "Accept ICMP redirects disabled"
    sysctl_check "3.2.3" 1 "net.ipv4.conf.all.secure_redirects"    "0" "Secure ICMP redirects disabled"
    sysctl_check "3.2.4" 1 "net.ipv4.conf.all.log_martians"        "1" "Martian packets logged"
    sysctl_check "3.2.5" 1 "net.ipv4.conf.all.rp_filter"           "1" "Reverse path filtering enabled"
    sysctl_check "3.2.6" 1 "net.ipv4.icmp_echo_ignore_broadcasts"  "1" "ICMP broadcast echo ignored"
    sysctl_check "3.2.7" 1 "net.ipv4.icmp_ignore_bogus_error_responses" "1" "Bogus ICMP error responses ignored"
    sysctl_check "3.2.8" 1 "net.ipv4.tcp_syncookies"               "1" "SYN flood protection (TCP syncookies) enabled"
    sysctl_check "3.3.1" 2 "net.ipv6.conf.all.accept_ra"           "0" "IPv6 Router Advertisements not accepted"
    sysctl_check "3.3.2" 2 "net.ipv6.conf.all.accept_redirects"    "0" "IPv6 redirects not accepted"

    # 3.4  Firewall
    section_header "3.4" "Firewall"
    if systemctl is-active ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
        record_result "3.4.1" 1 "UFW firewall active" PASS
    elif systemctl is-active firewalld &>/dev/null; then
        record_result "3.4.1" 1 "Firewalld firewall active" PASS
    elif iptables -L 2>/dev/null | grep -qv "Chain INPUT (policy ACCEPT)"; then
        record_result "3.4.1" 1 "iptables has non-default rules" PASS
    else
        record_result "3.4.1" 1 "Firewall active (ufw/firewalld/iptables)" FAIL \
            "Enable a firewall: ufw enable  OR  systemctl enable --now firewalld"
        if [[ "$OS_FAMILY" == "debian" ]]; then
            prompt_fix "3.4.1" "Enable UFW" "ufw --force enable"
        else
            prompt_fix "3.4.1" "Enable firewalld" "systemctl enable --now firewalld"
        fi
    fi

    # Check for wireless interfaces on servers
    if ip link show | grep -q "wlan\|wifi\|wlp"; then
        record_result "3.5" 2 "Wireless interfaces present" WARN \
            "Consider disabling wireless on servers: rfkill block wifi"
    else
        record_result "3.5" 2 "No wireless interfaces detected" PASS
    fi
}

# ── SECTION 4: Logging & Auditing ────────────────────────────────────────────
section_4() {
    section_header "4" "Logging & Auditing"

    # 4.1 auditd
    if command -v auditctl &>/dev/null; then
        record_result "4.1.1" 1 "auditd installed" PASS
    else
        record_result "4.1.1" 1 "auditd installed" FAIL "Install: apt/yum install auditd"
        if [[ "$OS_FAMILY" == "debian" ]]; then
            prompt_fix "4.1.1" "Install auditd" "apt-get install -y auditd audispd-plugins"
        else
            prompt_fix "4.1.1" "Install auditd" "yum install -y audit audit-libs"
        fi
    fi

    if systemctl is-active auditd &>/dev/null; then
        record_result "4.1.2" 1 "auditd service active" PASS
    else
        record_result "4.1.2" 1 "auditd service active" FAIL "systemctl enable --now auditd"
        prompt_fix "4.1.2" "Enable auditd" "systemctl enable --now auditd"
    fi

    # Check audit rules for key events
    local audit_rules=""
    command -v auditctl &>/dev/null && audit_rules=$(auditctl -l 2>/dev/null || cat /etc/audit/rules.d/*.rules 2>/dev/null || true)

    local -A audit_checks=(
        ["4.1.4 sudoers changes"]="/etc/sudoers"
        ["4.1.5 privileged command audit"]="execve"
        ["4.1.6 su/sudo use"]="\/usr\/bin\/su\|\/usr\/bin\/sudo"
        ["4.1.7 kernel module loading"]="init_module\|delete_module"
    )
    for desc_id in "${!audit_checks[@]}"; do
        if echo "$audit_rules" | grep -q "${audit_checks[$desc_id]}"; then
            record_result "$desc_id" 2 "Audit rule: $desc_id" PASS
        else
            record_result "$desc_id" 2 "Audit rule: $desc_id" WARN \
                "No matching audit rule found — check /etc/audit/rules.d/"
        fi
    done

    # 4.2  rsyslog / journald
    section_header "4.2" "Logging"
    if systemctl is-active rsyslog syslog-ng &>/dev/null; then
        record_result "4.2.1" 1 "Syslog service active (rsyslog/syslog-ng)" PASS
    elif systemctl is-active systemd-journald &>/dev/null; then
        record_result "4.2.1" 1 "Journald active (fallback)" WARN \
            "Consider installing rsyslog for persistent remote logging"
    else
        record_result "4.2.1" 1 "Syslog service active" FAIL \
            "Install rsyslog: apt/yum install rsyslog"
    fi

    # Log permissions
    local log_perms
    log_perms=$(stat -c "%a" /var/log 2>/dev/null || echo "???")
    if [[ "$log_perms" == "755" || "$log_perms" == "750" || "$log_perms" == "700" ]]; then
        record_result "4.2.3" 1 "/var/log permissions OK ($log_perms)" PASS
    else
        record_result "4.2.3" 1 "/var/log permissions correct" FAIL "Current: $log_perms, expected ≤ 755"
        prompt_fix "4.2.3" "Fix /var/log permissions" "chmod g-wx,o-rwx /var/log"
    fi
}

# ── SECTION 5: Access Control ─────────────────────────────────────────────────
section_5() {
    section_header "5" "Access, Authentication & Authorisation"

    # 5.1  cron
    if systemctl is-enabled cron crond &>/dev/null 2>&1 | grep -q enabled; then
        record_result "5.1.1" 1 "Cron daemon enabled" PASS
    elif systemctl is-active cron crond &>/dev/null; then
        record_result "5.1.1" 1 "Cron daemon enabled" PASS
    else
        record_result "5.1.1" 1 "Cron daemon enabled" WARN \
            "Cron not enabled — if scheduled jobs are needed: systemctl enable cron"
    fi

    local cron_perms
    for f in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        if [[ -e "$f" ]]; then
            cron_perms=$(stat -c "%a %U %G" "$f" 2>/dev/null)
            if echo "$cron_perms" | grep -qE "^[0-6][0-9]{2} root root$|^[0-7]00 root root$"; then
                record_result "5.1.2.$f" 1 "Cron $f owned root:root, restricted" PASS
            else
                record_result "5.1.2.$f" 1 "Cron $f owned root:root, restricted" FAIL \
                    "Current: $cron_perms — chmod og-rwx $f && chown root:root $f"
                prompt_fix "5.1.2.$f" "Restrict cron $f" "chown root:root $f && chmod og-rwx $f"
            fi
        fi
    done

    # 5.2  SSH
    section_header "5.2" "SSH Server Configuration"
    local sshd_cfg="/etc/ssh/sshd_config"

    sshd_check() {
        local id="$1" lvl="$2" param="$3" expected="$4" desc="$5" fix="${6:-}"
        local val
        val=$(sshd -T 2>/dev/null | grep -i "^${param}\b" | awk '{print tolower($2)}' | head -1)
        if [[ "${val,,}" == "${expected,,}" ]]; then
            record_result "$id" "$lvl" "$desc" PASS
        else
            record_result "$id" "$lvl" "$desc" FAIL \
                "Current: '${val:-unset}', expected: '$expected'"
            if [[ -n "$fix" ]]; then
                prompt_fix "$id" "$desc" "sed -i 's/^#*\s*${param}.*/${param} ${expected}/gI' $sshd_cfg && systemctl restart sshd"
            fi
        fi
    }

    # Permissions on sshd_config
    local ssh_perms
    ssh_perms=$(stat -c "%a" "$sshd_cfg" 2>/dev/null || echo "???")
    if [[ "$ssh_perms" -le 600 ]]; then
        record_result "5.2.1" 1 "sshd_config permissions ≤ 600" PASS
    else
        record_result "5.2.1" 1 "sshd_config permissions ≤ 600" FAIL "Current: $ssh_perms"
        prompt_fix "5.2.1" "Restrict sshd_config" "chmod 600 $sshd_cfg && chown root:root $sshd_cfg"
    fi

    sshd_check "5.2.2"  1 "LogLevel"                  "INFO"  "SSH LogLevel set to INFO"          "yes"
    sshd_check "5.2.4"  1 "X11Forwarding"             "no"    "SSH X11 forwarding disabled"       "yes"
    sshd_check "5.2.5"  1 "MaxAuthTries"              "4"     "SSH MaxAuthTries ≤ 4"              "yes"
    sshd_check "5.2.6"  1 "IgnoreRhosts"              "yes"   "SSH IgnoreRhosts enabled"          "yes"
    sshd_check "5.2.7"  1 "HostbasedAuthentication"  "no"    "SSH HostbasedAuth disabled"         "yes"
    sshd_check "5.2.8"  1 "PermitRootLogin"           "no"    "SSH root login disabled"           "yes"
    sshd_check "5.2.9"  1 "PermitEmptyPasswords"      "no"    "SSH empty passwords disabled"      "yes"
    sshd_check "5.2.10" 1 "PermitUserEnvironment"     "no"    "SSH user environment disabled"     "yes"
    sshd_check "5.2.14" 1 "AllowTcpForwarding"        "no"    "SSH TCP forwarding disabled"       "yes"
    sshd_check "5.2.16" 1 "ClientAliveInterval"       "300"   "SSH idle timeout ≤ 300s"           "yes"
    sshd_check "5.2.17" 1 "LoginGraceTime"            "60"    "SSH login grace time ≤ 60s"        "yes"
    sshd_check "5.2.20" 1 "AllowAgentForwarding"      "no"    "SSH agent forwarding disabled"     "yes"

    # Check approved ciphers
    local ssh_ciphers
    ssh_ciphers=$(sshd -T 2>/dev/null | grep "^ciphers" | head -1)
    local bad_ciphers=("arcfour" "des" "3des" "rc4" "blowfish")
    local cipher_ok=true
    for bc in "${bad_ciphers[@]}"; do
        echo "$ssh_ciphers" | grep -qi "$bc" && cipher_ok=false && break
    done
    if $cipher_ok; then
        record_result "5.2.11" 1 "SSH uses only approved ciphers (no weak ciphers)" PASS
    else
        record_result "5.2.11" 1 "SSH uses only approved ciphers" FAIL \
            "Weak cipher detected. Set Ciphers to aes128-ctr,aes192-ctr,aes256-ctr,... in sshd_config"
    fi

    # 5.3  PAM
    section_header "5.3" "PAM / Password Policy"

    local login_defs="/etc/login.defs"
    # PASS_MAX_DAYS
    local max_days
    max_days=$(grep "^PASS_MAX_DAYS" "$login_defs" 2>/dev/null | awk '{print $2}')
    if [[ -n "$max_days" && "$max_days" -le 365 ]]; then
        record_result "5.3.1" 1 "Password max age ≤ 365 days (PASS_MAX_DAYS=$max_days)" PASS
    else
        record_result "5.3.1" 1 "Password max age ≤ 365 days" FAIL \
            "Current: ${max_days:-unset}. Set PASS_MAX_DAYS 365 in $login_defs"
        prompt_fix "5.3.1" "Set PASS_MAX_DAYS" "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/' $login_defs"
    fi

    local min_days
    min_days=$(grep "^PASS_MIN_DAYS" "$login_defs" 2>/dev/null | awk '{print $2}')
    if [[ -n "$min_days" && "$min_days" -ge 1 ]]; then
        record_result "5.3.2" 1 "Password min age ≥ 1 day (PASS_MIN_DAYS=$min_days)" PASS
    else
        record_result "5.3.2" 1 "Password min age ≥ 1 day" FAIL \
            "Current: ${min_days:-unset}. Set PASS_MIN_DAYS 1 in $login_defs"
        prompt_fix "5.3.2" "Set PASS_MIN_DAYS" "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' $login_defs"
    fi

    # Password hashing
    local hash_method
    hash_method=$(grep "^ENCRYPT_METHOD" "$login_defs" 2>/dev/null | awk '{print $2}')
    if [[ "${hash_method^^}" == "SHA512" || "${hash_method^^}" == "YESCRYPT" ]]; then
        record_result "5.3.4" 1 "Password hashing: $hash_method" PASS
    else
        record_result "5.3.4" 1 "Password hashing SHA-512 or yescrypt" FAIL \
            "Current: ${hash_method:-unset}. Set ENCRYPT_METHOD SHA512 in $login_defs"
        prompt_fix "5.3.4" "Set SHA-512 password hashing" "sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' $login_defs || echo 'ENCRYPT_METHOD SHA512' >> $login_defs"
    fi

    # pam_faillock / pam_tally2
    if grep -r "pam_faillock\|pam_tally2" /etc/pam.d/ &>/dev/null; then
        record_result "5.3.5" 1 "Account lockout on failed attempts configured" PASS
    else
        record_result "5.3.5" 1 "Account lockout on failed attempts configured" FAIL \
            "Configure pam_faillock in /etc/pam.d/system-auth or /etc/pam.d/common-auth"
    fi

    # Password complexity (pwquality)
    if [[ -f /etc/security/pwquality.conf ]]; then
        local minlen
        minlen=$(grep "^minlen" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
        if [[ -n "$minlen" && "$minlen" -ge 14 ]]; then
            record_result "5.3.6" 1 "Password minimum length ≥ 14 (minlen=$minlen)" PASS
        else
            record_result "5.3.6" 1 "Password minimum length ≥ 14" FAIL \
                "Current minlen: ${minlen:-unset}. Set minlen=14 in /etc/security/pwquality.conf"
            prompt_fix "5.3.6" "Set password minlen=14" "sed -i 's/^#*\s*minlen.*/minlen = 14/' /etc/security/pwquality.conf"
        fi
    else
        record_result "5.3.6" 1 "pwquality.conf present" FAIL \
            "Install libpwquality and create /etc/security/pwquality.conf"
    fi

    # 5.4  User accounts
    section_header "5.4" "User Accounts & Environment"

    # Root account
    local root_locked
    root_locked=$(passwd -S root 2>/dev/null | awk '{print $2}')
    # Allow P (password set, normal for root), L (locked), or check for direct root login preference
    # CIS wants no one to log in as root directly via password but root account must exist
    if [[ "$root_locked" == "L" ]]; then
        record_result "5.4.1" 1 "Root account password locked (direct login via su only)" PASS
    else
        record_result "5.4.1" 1 "Root account password locked" WARN \
            "Consider locking root: passwd -l root (ensure sudo access exists first)"
    fi

    # UID 0 accounts (should only be root)
    local uid0
    uid0=$(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null)
    if [[ "$uid0" == "root" ]]; then
        record_result "5.4.2" 1 "Only root has UID 0" PASS
    else
        record_result "5.4.2" 1 "Only root has UID 0" FAIL \
            "Non-root UID 0 accounts: $uid0"
    fi

    # Users without passwords
    local no_pass
    no_pass=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)
    if [[ -z "$no_pass" ]]; then
        record_result "5.4.3" 1 "No accounts with empty passwords" PASS
    else
        record_result "5.4.3" 1 "No accounts with empty passwords" FAIL \
            "Empty password accounts: $no_pass"
    fi

    # umask
    local sys_umask
    sys_umask=$(grep "^UMASK" "$login_defs" 2>/dev/null | awk '{print $2}')
    if [[ "$sys_umask" == "027" || "$sys_umask" == "077" ]]; then
        record_result "5.4.4" 1 "Default umask ≥ 027 ($sys_umask)" PASS
    else
        record_result "5.4.4" 1 "Default umask ≥ 027" FAIL \
            "Current: ${sys_umask:-unset}. Set UMASK 027 in $login_defs"
        prompt_fix "5.4.4" "Set UMASK 027" "sed -i 's/^UMASK.*/UMASK\t\t027/' $login_defs"
    fi

    # Inactive accounts lock
    local inactive
    inactive=$(useradd -D 2>/dev/null | grep INACTIVE | cut -d= -f2)
    if [[ -n "$inactive" && "$inactive" -le 30 && "$inactive" -gt 0 ]]; then
        record_result "5.4.5" 1 "Inactive account lock ≤ 30 days ($inactive)" PASS
    else
        record_result "5.4.5" 1 "Inactive account lock ≤ 30 days" FAIL \
            "Current: ${inactive:-unset}. Set: useradd -D -f 30"
        prompt_fix "5.4.5" "Lock inactive accounts after 30 days" "useradd -D -f 30"
    fi
}

# ── SECTION 6: System Maintenance ────────────────────────────────────────────
section_6() {
    section_header "6" "System Maintenance — File Permissions & User/Group Settings"

    # Key file permissions
    declare -A file_perms=(
        ["/etc/passwd"]="644 root root"
        ["/etc/shadow"]="640 root shadow|000 root root|000 root shadow"
        ["/etc/group"]="644 root root"
        ["/etc/gshadow"]="640 root shadow|000 root root|000 root shadow"
        ["/etc/passwd-"]="644 root root"
        ["/etc/shadow-"]="000 root root|640 root shadow"
        ["/etc/group-"]="644 root root"
    )

    for file in "${!file_perms[@]}"; do
        if [[ ! -f "$file" ]]; then
            record_result "6.1.$file" 1 "Permissions on $file" SKIP "File not found"
            continue
        fi
        local actual_stat
        actual_stat=$(stat -c "%a %U %G" "$file" 2>/dev/null)
        local expected="${file_perms[$file]}"
        local ok=false
        IFS='|' read -ra expected_vals <<< "$expected"
        for ev in "${expected_vals[@]}"; do
            [[ "$actual_stat" == "$ev" ]] && ok=true && break
        done
        if $ok; then
            record_result "6.1.$file" 1 "Permissions on $file OK ($actual_stat)" PASS
        else
            record_result "6.1.$file" 1 "Permissions on $file" FAIL \
                "Current: $actual_stat, expected: $expected"
        fi
    done

    # World-writable files
    local wwfiles
    wwfiles=$(find / -xdev -type f -perm -0002 2>/dev/null | grep -v "^/proc\|^/sys\|^/dev" | head -20)
    if [[ -z "$wwfiles" ]]; then
        record_result "6.1.10" 1 "No world-writable files found" PASS
    else
        record_result "6.1.10" 1 "No world-writable files found" WARN \
            "$(echo "$wwfiles" | wc -l) world-writable file(s) found (first 20 shown)"
        echo "$wwfiles" | while read -r wf; do
            echo -e "         ${YELLOW}  → $wf${RESET}"
        done
    fi

    # World-writable directories without sticky bit
    local ww_dirs
    ww_dirs=$(find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | grep -v "^/proc\|^/sys\|^/dev" | head -10)
    if [[ -z "$ww_dirs" ]]; then
        record_result "6.1.11" 1 "World-writable dirs have sticky bit" PASS
    else
        record_result "6.1.11" 1 "World-writable dirs have sticky bit" FAIL \
            "$(echo "$ww_dirs" | wc -l) dir(s) lack sticky bit — chmod +t <dir>"
    fi

    # Unowned files
    local unowned
    unowned=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | grep -v "^/proc\|^/sys" | head -10)
    if [[ -z "$unowned" ]]; then
        record_result "6.1.12" 1 "No unowned files or directories" PASS
    else
        record_result "6.1.12" 1 "No unowned files or directories" WARN \
            "$(echo "$unowned" | wc -l) unowned file(s) found"
    fi

    # 6.2  User and Group Settings
    section_header "6.2" "User & Group Settings"

    # Duplicate UIDs
    local dup_uids
    dup_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
    if [[ -z "$dup_uids" ]]; then
        record_result "6.2.1" 1 "No duplicate UIDs in /etc/passwd" PASS
    else
        record_result "6.2.1" 1 "No duplicate UIDs in /etc/passwd" FAIL \
            "Duplicate UIDs: $dup_uids"
    fi

    # Duplicate GIDs
    local dup_gids
    dup_gids=$(awk -F: '{print $3}' /etc/group | sort | uniq -d)
    if [[ -z "$dup_gids" ]]; then
        record_result "6.2.2" 1 "No duplicate GIDs in /etc/group" PASS
    else
        record_result "6.2.2" 1 "No duplicate GIDs in /etc/group" FAIL \
            "Duplicate GIDs: $dup_gids"
    fi

    # Duplicate usernames
    local dup_users
    dup_users=$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d)
    if [[ -z "$dup_users" ]]; then
        record_result "6.2.3" 1 "No duplicate usernames" PASS
    else
        record_result "6.2.3" 1 "No duplicate usernames" FAIL "Duplicates: $dup_users"
    fi

    # Home directories exist and are owned correctly
    local home_issues=0
    while IFS=: read -r user _ uid gid _ home shell; do
        [[ "$uid" -lt 1000 ]] && continue  # skip system accounts
        [[ "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/false" ]] && continue
        if [[ ! -d "$home" ]]; then
            echo -e "  ${YELLOW}  ↳ $user: home dir $home does not exist${RESET}"
            ((home_issues++))
        fi
    done < /etc/passwd
    if [[ "$home_issues" -eq 0 ]]; then
        record_result "6.2.7" 1 "All interactive users have existing home directories" PASS
    else
        record_result "6.2.7" 1 "All interactive users have existing home directories" FAIL \
            "$home_issues user(s) missing home directories"
    fi
}

# ── REPORT GENERATION ─────────────────────────────────────────────────────────
generate_report() {
    local total=$((PASS + FAIL + WARN + SKIP))
    local score=0
    [[ $((PASS + FAIL + WARN)) -gt 0 ]] && score=$(( (PASS * 100) / (PASS + FAIL + WARN) ))

    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN}  AUDIT SUMMARY${RESET}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${RESET}"
    echo -e "  Host:     $(hostname)"
    echo -e "  OS:       $OS_ID $OS_VER  ($OS_FAMILY)"
    echo -e "  Date:     $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "  Level:    $LEVEL"
    echo ""
    echo -e "  ${GREEN}${BOLD}PASS:${RESET}  $PASS"
    echo -e "  ${RED}${BOLD}FAIL:${RESET}  $FAIL"
    echo -e "  ${YELLOW}${BOLD}WARN:${RESET}  $WARN"
    echo -e "  ${CYAN}${BOLD}SKIP:${RESET}  $SKIP"
    echo -e "  ${BOLD}TOTAL:${RESET} $total"
    echo ""
    if   [[ "$score" -ge 85 ]]; then echo -e "  ${GREEN}${BOLD}Compliance Score: $score% ✔ GOOD${RESET}"
    elif [[ "$score" -ge 60 ]]; then echo -e "  ${YELLOW}${BOLD}Compliance Score: $score% ⚠ NEEDS WORK${RESET}"
    else                              echo -e "  ${RED}${BOLD}Compliance Score: $score% ✘ CRITICAL${RESET}"; fi
    echo ""
    echo -e "  Log file:  $LOG_FILE"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${RESET}"

    # Optionally write HTML report
    if [[ -n "$REPORT_FILE" ]]; then
        write_html_report "$score" "$total"
        echo -e "  ${GREEN}HTML report: $REPORT_FILE${RESET}"
    fi
}

write_html_report() {
    local score="$1" total="$2"
    local color
    [[ "$score" -ge 85 ]] && color="#22c55e" || { [[ "$score" -ge 60 ]] && color="#f59e0b" || color="#ef4444"; }
    cat > "$REPORT_FILE" <<HTML
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>CIS Baseline Report — $(hostname)</title>
<style>
  body{font-family:monospace;background:#0f172a;color:#e2e8f0;padding:2rem;margin:0}
  h1{color:#38bdf8;border-bottom:2px solid #38bdf8;padding-bottom:.5rem}
  .summary{display:flex;gap:1.5rem;margin:1rem 0;flex-wrap:wrap}
  .stat{background:#1e293b;padding:1rem 1.5rem;border-radius:.5rem;text-align:center}
  .stat span{display:block;font-size:2rem;font-weight:700}
  .pass{color:#22c55e}.fail{color:#ef4444}.warn{color:#f59e0b}.skip{color:#38bdf8}
  .score{font-size:3rem;font-weight:800;color:${color}}
  table{width:100%;border-collapse:collapse;margin-top:1.5rem;font-size:.85rem}
  th{background:#1e3a5f;padding:.5rem 1rem;text-align:left;position:sticky;top:0}
  tr:nth-child(even){background:#1e293b}
  td{padding:.4rem 1rem;border-bottom:1px solid #334155}
  .PASS{color:#22c55e}.FAIL{color:#ef4444}.WARN{color:#f59e0b}.SKIP{color:#64748b}
  .badge{display:inline-block;padding:.1rem .5rem;border-radius:.25rem;font-size:.75rem;font-weight:600}
</style></head><body>
<h1>🛡 CIS Linux Security Baseline Report</h1>
<p>Host: <b>$(hostname)</b> &nbsp;|&nbsp; OS: <b>$OS_ID $OS_VER</b> &nbsp;|&nbsp; Date: <b>$(date '+%Y-%m-%d %H:%M:%S')</b> &nbsp;|&nbsp; Level: <b>$LEVEL</b></p>
<div class="summary">
  <div class="stat"><span class="score">${score}%</span>Compliance</div>
  <div class="stat"><span class="pass">$PASS</span>PASS</div>
  <div class="stat"><span class="fail">$FAIL</span>FAIL</div>
  <div class="stat"><span class="warn">$WARN</span>WARN</div>
  <div class="stat"><span class="skip">$SKIP</span>SKIP</div>
  <div class="stat"><span>$total</span>TOTAL</div>
</div>
<table>
<tr><th>ID</th><th>L</th><th>Description</th><th>Status</th><th>Detail</th></tr>
HTML
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r id lvl desc status detail <<< "$r"
        echo "<tr><td>$id</td><td>$lvl</td><td>$desc</td><td class='$status'><b>$status</b></td><td>${detail:-—}</td></tr>" >> "$REPORT_FILE"
    done
    echo "</table></body></html>" >> "$REPORT_FILE"
}

# ── ARGUMENT PARSING ──────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --audit-only          Run checks only, do not prompt for fixes
  --level <1|2>         CIS level to audit (default: 1)
  --section <n>         Run only section n (1-6)
  --report <file.html>  Save HTML report to file
  --help                Show this help

Examples:
  sudo $0 --audit-only
  sudo $0 --level 2 --report /tmp/cis-report.html
  sudo $0 --section 5
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --audit-only)   AUDIT_ONLY=true ;;
        --level)        LEVEL="${2:-1}"; shift ;;
        --section)      SECTION_FILTER="${2:-}"; shift ;;
        --report)       REPORT_FILE="${2:-}"; shift ;;
        --help|-h)      usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
    shift
done

# ── MAIN ──────────────────────────────────────────────────────────────────────
if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root.${RESET}"
    echo "  Try: sudo $0"
    exit 1
fi

print_banner
detect_os

echo -e "  ${BOLD}Detected OS:${RESET} $OS_ID $OS_VER ($OS_FAMILY)"
echo -e "  ${BOLD}CIS Level:${RESET}   $LEVEL"
echo -e "  ${BOLD}Mode:${RESET}        $( $AUDIT_ONLY && echo 'Audit Only' || echo 'Audit + Interactive Remediation' )"
echo -e "  ${BOLD}Log:${RESET}         $LOG_FILE"
echo ""

if ! $AUDIT_ONLY; then
    echo -e "  ${YELLOW}⚠  Remediation mode: you will be prompted before any change is applied.${RESET}"
    echo -e "  ${YELLOW}   A backup snapshot is strongly recommended before proceeding.${RESET}"
    echo ""
    read -r -p "  Continue? [y/N] " confirm
    [[ "${confirm,,}" != "y" ]] && echo "Aborted." && exit 0
fi

touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/cis-baseline-$(date +%Y%m%d-%H%M%S).log"
log "=== CIS Baseline Tool v$TOOL_VERSION started on $(hostname) OS=$OS_ID$OS_VER level=$LEVEL ==="

run_section() {
    local sec="$1"
    should_run_section "$sec" || return 0
    "section_$sec"
}

run_section 1
run_section 2
run_section 3
run_section 4
run_section 5
run_section 6

generate_report
log "=== Completed: PASS=$PASS FAIL=$FAIL WARN=$WARN SKIP=$SKIP ==="
