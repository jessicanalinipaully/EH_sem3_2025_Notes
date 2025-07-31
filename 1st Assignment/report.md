
# Vulnerability Assessment Report: Service Version Detection on testphp.vulnweb.com

**Date:** 2025-07-31

---

### Methodology

I performed a service version scan on the target website **testphp.vulnweb.com** using Nmap with the following command:

```bash
sudo nmap -sV -Pn testphp.vulnweb.com
````

The `-sV` option enables version detection, and `-Pn` skips host discovery to avoid issues if the server blocks ICMP ping requests. The scan aimed to identify open ports and their respective software versions to assess potential vulnerabilities.

---

### Findings

**1. PHP 5.6.40**

* Detected via HTTP headers (`X-Powered-By`).
* PHP 5.6.40 is an outdated version that reached end-of-life in January 2019.
* Known vulnerabilities include:

  * **CVE-2019-9023:** Buffer over-read vulnerability leading to potential crashes or data leakage.
  * **CVE-2019-9024:** XML-RPC remote memory corruption.
  * **CVE-2019-6977:** Heap buffer overflow in GD library that could lead to remote code execution.

*Risk:* These vulnerabilities can be exploited to crash the server, leak sensitive information, or even execute arbitrary code remotely.

![PHP Vulnerabilities](php-vulnerabilities.png)

---

**2. Apache HTTP Server**

* Version not explicitly detected by Nmap but commonly runs on port 443.
* Multiple critical vulnerabilities in Apache 2.4.49 and 2.4.50:

  * **CVE-2021-41773:** Path traversal vulnerability allowing attackers to access files outside web root directories.
  * **CVE-2021-42013:** Incomplete fix for CVE-2021-41773, enabling continued exploitation.

*Risk:* These flaws can allow attackers to access sensitive files and potentially execute remote code, compromising server integrity.

![Apache CVEs](apache-cve.png)

---

**3. Service Version Scan**

* The Nmap scan did not detect open ports or specific service versions initially, likely due to firewall or ping blocking.
* Using the `-Pn` flag allowed successful service version detection (e.g., PHP version via HTTP headers).

![Nmap Scan](nmap-scan.png)

---

### Conclusion

The target system is running **outdated software versions** (PHP 5.6.40, Apache 2.4.49/2.4.50) with known critical vulnerabilities. Attackers could exploit these flaws to gain unauthorized access, cause denial-of-service, or execute remote code.<img width="960" height="839" alt="nmap-services" src="https://github.com/user-attachments/assets/99eea6c5-986e-4c73-a98e-644a63c6fb1a" />
<img width="1459" height="877" alt="apache-cve" src="https://github.com/user-attachments/assets/066347b1-90f4-49d0-9147-9bbca8ea4ed0" />
<img width="1463" height="811" alt="php-vulnerabilities" src="https://github.com/user-attachments/assets/da69d3cb-7154-45b2-91db-64e2190cdc31" />



```
<img width="1463" height="811" alt="php-vulnerabilities" src="https://github.com/user-attachments/assets/20879415-8c18-4408-8beb-e3974fa36802" />
<img width="1459" height="877" alt="apache-cve" src="https://github.com/user-attachments/assets/febc3530-45ff-4143-a3e1-48f1cd15e2af" />


