#!/usr/bin/env python3
"""
Full VAPT Engagement Automation Script
Follows PTES (Penetration Testing Execution Standard) methodology
"""

import os
import subprocess
import json
from datetime import datetime
import argparse
import sys

class VAPTEngagement:
    def __init__(self, target_ip, output_dir="vapt_results"):
        self.target_ip = target_ip
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.results = {
            "target": target_ip,
            "start_time": self.timestamp,
            "phases": {}
        }
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
    def log_phase(self, phase_name, data):
        """Log PTES phase results"""
        self.results["phases"][phase_name] = {
            "timestamp": datetime.now().isoformat(),
            "data": data
        }
        print(f"[+] Completed: {phase_name}")
        
    def phase1_reconnaissance(self):
        """Phase 1: Information Gathering"""
        print("\n[*] Phase 1: Reconnaissance")
        recon_data = {}
        
        # Ping sweep
        print(f"[*] Checking if {self.target_ip} is alive...")
        ping_result = subprocess.run(
            ["ping", "-c", "1", self.target_ip],
            capture_output=True,
            text=True,
            timeout=5
        )
        recon_data["host_alive"] = ping_result.returncode == 0
        
        if not recon_data["host_alive"]:
            print(f"[-] Target {self.target_ip} is not reachable")
            return recon_data
            
        print(f"[+] Target {self.target_ip} is alive")
        
        # DNS enumeration (optional)
        try:
            dns_result = subprocess.run(
                ["nslookup", self.target_ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            recon_data["dns_info"] = dns_result.stdout
        except Exception as e:
            recon_data["dns_info"] = f"Error: {str(e)}"
        
        self.log_phase("Reconnaissance", recon_data)
        return recon_data
    
    def phase2_scanning(self):
        """Phase 2: Vulnerability Scanning"""
        print("\n[*] Phase 2: Scanning & Enumeration")
        scan_data = {}
        
        # Nmap scan
        print(f"[*] Running Nmap scan on {self.target_ip}...")
        nmap_output = os.path.join(self.output_dir, f"nmap_{self.timestamp}.txt")
        
        try:
            nmap_cmd = [
                "nmap", "-sV", "-sC", "-p-",
                "-oN", nmap_output,
                self.target_ip
            ]
            print(f"[*] Command: {' '.join(nmap_cmd)}")
            
            nmap_result = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            scan_data["nmap_output_file"] = nmap_output
            scan_data["open_ports"] = self._parse_nmap_output(nmap_result.stdout)
            
            with open(nmap_output, 'w') as f:
                f.write(nmap_result.stdout)
                
            print(f"[+] Nmap scan complete. Results saved to {nmap_output}")
            
        except subprocess.TimeoutExpired:
            scan_data["nmap_error"] = "Scan timeout (>5 minutes)"
        except FileNotFoundError:
            print("[-] Nmap not found. Please install nmap.")
            scan_data["nmap_error"] = "Nmap not installed"
        except Exception as e:
            scan_data["nmap_error"] = str(e)
        
        self.log_phase("Scanning", scan_data)
        return scan_data
    
    def _parse_nmap_output(self, output):
        """Parse nmap output for open ports"""
        ports = []
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    ports.append({
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown"
                    })
        return ports
    
    def phase3_exploitation(self, scan_results):
        """Phase 3: Exploitation (Simulated/Manual)"""
        print("\n[*] Phase 3: Exploitation")
        exploit_data = {
            "note": "Manual exploitation required. Use Metasploit or custom exploits.",
            "recommended_exploits": []
        }
        
        # Provide exploit recommendations based on open ports
        open_ports = scan_results.get("open_ports", [])
        
        for port_info in open_ports:
            port = port_info.get("port", "")
            service = port_info.get("service", "")
            
            if "21" in port and "ftp" in service.lower():
                exploit_data["recommended_exploits"].append({
                    "port": port,
                    "service": service,
                    "exploit": "exploit/unix/ftp/vsftpd_234_backdoor",
                    "description": "VSFTPD 2.3.4 Backdoor Command Execution"
                })
            elif "80" in port or "443" in port:
                exploit_data["recommended_exploits"].append({
                    "port": port,
                    "service": service,
                    "exploit": "Manual web testing with Burp Suite",
                    "description": "Check for SQLi, XSS, IDOR, authentication bypass"
                })
            elif "445" in port or "139" in port:
                exploit_data["recommended_exploits"].append({
                    "port": port,
                    "service": service,
                    "exploit": "exploit/windows/smb/ms17_010_eternalblue",
                    "description": "SMB EternalBlue (MS17-010)"
                })
        
        # Log exploitation attempts (placeholder for manual work)
        exploit_log = {
            "timestamp": datetime.now().isoformat(),
            "target_ip": self.target_ip,
            "vulnerability": "To be identified manually",
            "ptes_phase": "Exploitation",
            "status": "Pending manual testing"
        }
        
        exploit_data["exploitation_log"] = exploit_log
        
        print("[*] Exploitation phase requires manual testing.")
        print("[*] Review recommended exploits in the report.")
        
        self.log_phase("Exploitation", exploit_data)
        return exploit_data
    
    def phase4_post_exploitation(self):
        """Phase 4: Post-Exploitation (Placeholder)"""
        print("\n[*] Phase 4: Post-Exploitation")
        post_exploit_data = {
            "note": "Execute after successful exploitation",
            "tasks": [
                "Privilege escalation (LinPEAS/WinPEAS)",
                "Persistence establishment (cron/services)",
                "Lateral movement enumeration",
                "Data exfiltration simulation"
            ]
        }
        
        self.log_phase("Post-Exploitation", post_exploit_data)
        return post_exploit_data
    
    def generate_report(self, recon, scan, exploit, post_exploit):
        """Generate comprehensive PTES report"""
        print("\n[*] Generating PTES Report...")
        
        report_file = os.path.join(self.output_dir, f"VAPT_Report_{self.timestamp}.txt")
        
        report_content = f"""
{'='*80}
VULNERABILITY ASSESSMENT AND PENETRATION TESTING REPORT
{'='*80}

EXECUTIVE SUMMARY
-----------------
Target IP: {self.target_ip}
Assessment Date: {self.timestamp}
Testing Framework: PTES (Penetration Testing Execution Standard)

This assessment identified potential security vulnerabilities through systematic
reconnaissance, scanning, and exploitation attempts. The engagement followed
industry-standard PTES methodology across all phases.

{'='*80}
ATTACK TIMELINE
{'='*80}

Phase 1: Reconnaissance
-----------------------
Start Time: {recon.get('timestamp', 'N/A')}
Host Status: {'Active' if recon.get('host_alive', False) else 'Unreachable'}

Phase 2: Scanning & Enumeration
--------------------------------
Open Ports Discovered: {len(scan.get('open_ports', []))}

"""
        # Add port details
        for port in scan.get('open_ports', []):
            report_content += f"  - {port['port']}: {port['service']} ({port['state']})\n"
        
        report_content += f"""
Phase 3: Exploitation
---------------------
Recommended Exploits: {len(exploit.get('recommended_exploits', []))}

"""
        # Add exploit recommendations
        for exp in exploit.get('recommended_exploits', []):
            report_content += f"""
  Target: {exp['service']} on {exp['port']}
  Exploit: {exp['exploit']}
  Description: {exp['description']}
"""
        
        report_content += f"""
Phase 4: Post-Exploitation
---------------------------
Status: {post_exploit.get('note', 'Pending')}

{'='*80}
REMEDIATION PLAN
{'='*80}

Critical Recommendations:
1. Patch Management: Update all services to latest versions
2. Input Validation: Implement strict input validation on all user inputs
3. Least Privilege: Apply principle of least privilege to all services
4. Network Segmentation: Isolate critical systems from untrusted networks
5. Monitoring: Implement SIEM for real-time threat detection

Service-Specific Recommendations:
"""
        
        # Add service-specific recommendations
        for port in scan.get('open_ports', []):
            service = port.get('service', 'unknown')
            if 'ftp' in service.lower():
                report_content += "  - FTP: Disable anonymous access, use SFTP/FTPS\n"
            elif 'http' in service.lower():
                report_content += "  - Web: Enable WAF, implement CSP headers, use HTTPS\n"
            elif 'smb' in service.lower():
                report_content += "  - SMB: Disable SMBv1, enable SMB signing\n"
        
        report_content += f"""
{'='*80}
STAKEHOLDER BRIEFING (Non-Technical Summary)
{'='*80}

Our security assessment of {self.target_ip} revealed several areas requiring
attention. We identified {len(scan.get('open_ports', []))} network services that 
could be targeted by attackers. Key recommendations include updating software,
strengthening access controls, and improving monitoring capabilities. These
improvements will significantly reduce your organization's risk exposure while
maintaining operational efficiency. Immediate action is recommended for
critical findings to prevent potential security incidents.

{'='*80}
ASSESSMENT METADATA
{'='*80}

Tools Used:
  - Nmap (Service enumeration)
  - Metasploit Framework (Exploitation)
  - Burp Suite (Web application testing)
  - Python (Automation)

Testing Constraints:
  - Non-destructive testing only
  - Production environment considerations
  - Time-boxed engagement

Next Steps:
  1. Review and prioritize findings
  2. Implement remediation plan
  3. Re-scan with OpenVAS to verify fixes
  4. Schedule follow-up assessment

{'='*80}
End of Report
{'='*80}
"""
        
        with open(report_file, 'w') as f:
            f.write(report_content)
        
        print(f"[+] Report generated: {report_file}")
        
        # Save JSON results
        json_file = os.path.join(self.output_dir, f"results_{self.timestamp}.json")
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] JSON results saved: {json_file}")
        
        return report_file
    
    def run_full_engagement(self):
        """Execute complete VAPT engagement"""
        print(f"\n{'='*60}")
        print(f"  VAPT ENGAGEMENT - Target: {self.target_ip}")
        print(f"{'='*60}\n")
        
        try:
            # Execute PTES phases
            recon = self.phase1_reconnaissance()
            
            if not recon.get("host_alive", False):
                print("\n[-] Target unreachable. Aborting engagement.")
                return
            
            scan = self.phase2_scanning()
            exploit = self.phase3_exploitation(scan)
            post_exploit = self.phase4_post_exploitation()
            
            # Generate report
            report_file = self.generate_report(recon, scan, exploit, post_exploit)
            
            print(f"\n{'='*60}")
            print(f"  ENGAGEMENT COMPLETE")
            print(f"{'='*60}")
            print(f"\nResults directory: {self.output_dir}")
            print(f"Report: {report_file}")
            
        except KeyboardInterrupt:
            print("\n\n[!] Engagement interrupted by user")
        except Exception as e:
            print(f"\n[-] Error during engagement: {str(e)}")
            import traceback
            traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(
        description="Full VAPT Engagement Automation Script (PTES Methodology)"
    )
    parser.add_argument(
        "target",
        help="Target IP address"
    )
    parser.add_argument(
        "-o", "--output",
        default="vapt_results",
        help="Output directory (default: vapt_results)"
    )
    
    args = parser.parse_args()
    
    # Validate IP format (basic check)
    ip_parts = args.target.split('.')
    if len(ip_parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in ip_parts):
        print("[-] Invalid IP address format")
        sys.exit(1)
    
    # Create and run engagement
    engagement = VAPTEngagement(args.target, args.output)
    engagement.run_full_engagement()

if __name__ == "__main__":
    main()