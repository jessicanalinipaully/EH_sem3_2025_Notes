
# Vulnerability Assessment Report: Service Version Detection on testphp.vulnweb.com

**Date:** 2025-07-31

---

## 🎯 Methodology

I performed a service version scan on the target website `testphp.vulnweb.com` using Nmap.

### 🔧 Command Used:

```bash
sudo nmap -sV -Pn testphp.vulnweb.com
````

* `-sV`: Enables version detection
* `-Pn`: Skips ping checks (useful if ICMP is blocked)

This revealed services and versions running on the host, which I then researched for known CVEs.

---

## 🔍 Findings

### ✅ 1. PHP 5.6.40

* **Detected:** Via HTTP headers (`X-Powered-By`)
* **Status:** End-of-life (EOL) since Jan 2019
* **Known CVEs:**

  * `CVE-2019-9023`: Buffer over-read — may lead to crash or memory disclosure
  * `CVE-2019-9024`: XML-RPC remote memory corruption
  * `CVE-2019-6977`: Heap buffer overflow in the GD module

**🛑 Risk:** These vulnerabilities could allow remote attackers  to crash the service, leak data, or execute arbitrary code.

<img width="1463" height="811" alt="php-vulnerabilities" src="https://github.com/user-attachments/assets/59a27acd-c915-4513-a918-cc4b13697493" />


---

### ✅ 2. Apache HTTP Server

* **Detected:** Likely on port 443 (HTTPS), common with this host
* **Vulnerable Versions Identified:**

  * `Apache 2.4.49`: CVE-2021-41773
  * `Apache 2.4.50`: CVE-2021-42013

**🛑 Risk:** These versions allow path traversal, letting attackers access unauthorized files outside the web root. If CGI is enabled, they may also execute commands remotely.

<img width="1459" height="877" alt="apache-cve" src="https://github.com/user-attachments/assets/8339e030-df7c-4eee-bb33-3bb916691c56" />

---
### ✅ 3. Nmap Service Version Scan

- **Purpose:** Identify running services and their versions on `testphp.vulnweb.com`  
- **Tool Used:** Nmap

### 🔧 Command Used:

```bash
sudo nmap -sV -Pn testphp.vulnweb.com
````

* `-sV`: Enables version detection
* `-Pn`: Disables host discovery (useful if ICMP ping is blocked)

### 🧾 Output Summary:

* Port 80 (HTTP): PHP 5.6.40 detected via HTTP headers
* Port 443 (HTTPS): Apache HTTPD assumed (version inferred via CVE research)
* Other ports: closed or filtered

**🛑 Risk:** Identifying outdated services is crucial for vulnerability assessment. Using `-Pn` helps detect hosts behind firewalls that block ping.


<img width="960" height="839" alt="nmap-services" src="https://github.com/user-attachments/assets/f7fd22bd-61bc-4df3-b037-a1005eaed28b" />


---

## 📌 Conclusion

The vulnerability assessment on `testphp.vulnweb.com` revealed that the target is running several outdated and potentially vulnerable services:

- **PHP 5.6.40**, which has reached end-of-life and contains multiple critical vulnerabilities that could allow remote code execution, memory corruption, or denial of service.
- **Apache HTTP Server versions 2.4.49 and 2.4.50**, which are affected by serious path traversal vulnerabilities that could expose sensitive files or enable remote code execution if CGI is enabled.
- The use of outdated software significantly increases the attack surface and risk of compromise.

These findings highlight the importance of regular software updates and security patching to mitigate known vulnerabilities.

## ✅ Recommendation

- **Immediate patching or upgrading** of PHP to a supported and secure version (e.g., PHP 7.4 or later) is essential to close critical security gaps.
- Upgrade Apache HTTP Server to the latest stable release, ensuring all known CVEs are addressed.
- Consider disabling or restricting CGI modules unless absolutely necessary, to reduce risk.
- Implement additional security controls such as Web Application Firewalls (WAFs) to help filter and block malicious traffic.
- Regularly perform vulnerability scans and keep software up to date as part of a proactive security strategy.

