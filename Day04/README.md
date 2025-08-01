
## NAT - Network Address Translation
- Changes **private IPs** to **public** ones so devices can access the internet.
- Used by **routers**.

---

## Network Address
- A unique address for a device on a network (usually an **IP address**).

---

## Terminal
- **Command-line tool** to run commands.
- Used in **Kali Linux** and other operating systems.

---

## TCP vs UDP

| Feature     | TCP          | UDP               |
|------------|--------------|-------------------|
| Connection | Yes          | No                |
| Reliable   | Yes          | No                |
| Speed      | Slower       | Faster            |
| Ordered    | Yes          | No                |
| Examples   | Web, Email, SSH | DNS, Games, Video |

---

## Subnet / Network / IP / MAC

- **Subnet**: A smaller section of a network.
- **Network**: Group of connected devices.
- **IP Address**: Internet address for a device.
- **MAC Address**: Hardware ID of a device (physical address).

---

## IPv4
- **32-bit** address format.  
- Example: `192.168.1.1`

### Private IP Ranges:
- `10.0.0.0 – 10.255.255.255`
- `172.16.0.0 – 172.31.255.255`
- `192.168.0.0 – 192.168.255.255`

---

## Static vs Dynamic IP

- **Static**: Set manually, doesn't change.
- **Dynamic**: Assigned by router, can change.

---

## Port Forwarding
- Sends data from a **router’s public port** to a **device inside the network**.
- Used for **hosting games, websites**, etc.

---

## Payload & Backdoor

- **Payload**: The harmful part of malware (runs after system is hacked).
- **Backdoor**: A secret way to get into a system.

---

## UAC (User Access Control)
- Windows feature that **asks for permission** when software tries to make big system changes.

---

## Recon (Information Gathering)

- **Passive**: No contact with target (e.g., Google search).
- **Active**: Direct contact (e.g., Nmap scan).

### Websites for Info Gathering:
- [haveibeenpwned.com](https://haveibeenpwned.com) → Check if email/password is leaked  
- [archive.org](https://archive.org) → See old versions of websites (Wayback Machine)  
- [weakpass.com](https://weakpass.com) → Lists of weak passwords  

---

## Kali Linux - Nmap Commands

### Useful Flags/Options:
- `-Pn` → Don’t ping target, assume it’s up  
- `-A` → Aggressive scan (OS, services, etc.)  
- `-sV` → Find versions of services running  
- `-O` → OS detection  
- `-oN` → Save output to file  
- `--script` → Run scripts (e.g., for finding vulnerabilities)  
- `-vv` → More detailed output  
- `-p` → Specify ports (e.g., `-p 1-1000`)  
- `-sS` → Stealth (SYN) scan  
- `-sT` → Full TCP connect scan  

### Example Command:
```bash
nmap -Pn -A -sV -O --script vuln -vv -p 1-1000 192.168.1.1
