

# 🔧 Part 1: Installing VirtualBox

## ✅ Step 1: Download VirtualBox

1. Go to the official website: [https://www.virtualbox.org](https://www.virtualbox.org)
2. Click on **“Downloads”**.
3. Choose your operating system:

   * Windows hosts
   * macOS hosts
   * Linux distributions (Ubuntu/Debian-based or RedHat/Fedora-based)
4. Download the installer file.

## ✅ Step 2: Install VirtualBox

### On **Windows**:

1. Run the `.exe` file you downloaded.
2. Click **Next** through the setup screens.
3. Choose installation options (leave default unless you know what to change).
4. Click **Install**.
5. Allow any **driver installations** (click “Install” if prompted).
6. Click **Finish** to launch VirtualBox.

### On **macOS**:

1. Open the `.dmg` file.
2. Double-click the VirtualBox.pkg installer.
3. Follow on-screen instructions to install.
4. You might need to allow permissions in **System Preferences → Security & Privacy**.
5. Launch VirtualBox from Applications.

### On **Linux (Ubuntu/Debian)**:

Open Terminal and run:

```bash
sudo apt update
sudo apt install virtualbox
```

> Optional: Add VirtualBox Extension Pack from the website to enable USB 2.0/3.0, RDP, and more.

---

# 🐱‍💻 Part 2: Downloading Kali Linux ISO

## ✅ Step 1: Go to Kali Linux Official Site

* Visit: [https://www.kali.org/get-kali/](https://www.kali.org/get-kali/)
* Choose:

  * **Installer ISO** for full installation inside VirtualBox
  * **VirtualBox image** (pre-configured VM) for easier setup (skip to Part 4 if using this)

## ✅ Step 2: Download the 64-bit Installer ISO

Choose the appropriate file:

* Kali Linux **64-bit Installer**
* File type: `.iso`
* Size: \~4 GB

---

# 📦 Part 3: Creating a New Virtual Machine for Kali Linux

## ✅ Step 1: Open VirtualBox

* Click **New** to create a new virtual machine.

## ✅ Step 2: VM Configuration

* **Name**: Kali Linux
* **Machine Folder**: Leave as default
* **Type**: Linux
* **Version**: Debian (64-bit) *(Kali is based on Debian)*

## ✅ Step 3: Allocate Memory (RAM)

* Minimum: **2048 MB (2 GB)**
* Recommended: **4096 MB (4 GB)** or more if you have enough RAM

## ✅ Step 4: Create Virtual Hard Disk

* Select **Create a virtual hard disk now**
* Click **Create**

### Hard Disk Type:

* Choose **VDI (VirtualBox Disk Image)**

### Storage on Physical Hard Disk:

* Select **Dynamically allocated**

### Set Size:

* At least **20 GB**
* Recommended: **30-50 GB**

---

# 💿 Part 4: Install Kali Linux from ISO

## ✅ Step 1: Insert the Kali ISO into VM

1. Select your new Kali Linux VM.
2. Click **Settings > Storage**.
3. Under "Controller: IDE", click the empty disk icon.
4. On the right, click the disk icon → **Choose a disk file**.
5. Browse and select your **Kali Linux ISO**.

## ✅ Step 2: Start the Virtual Machine

* Select Kali VM → Click **Start**
* Kali installer will load

## ✅ Step 3: Install Kali Linux

### Choose:

* Graphical Install

### Steps in Installer:

1. Select Language, Region, and Keyboard layout
2. Enter hostname: `kali`
3. Domain name: Leave blank (optional)
4. Create a user:

   * Username: any (e.g., `student`)
   * Password: create a strong one
5. Set time zone
6. Partitioning:

   * Choose **Guided – use entire disk**
   * Select disk and choose **All files in one partition**
   * Finish partitioning and write changes to disk

### Wait for Base Installation to Complete

7. Choose whether to use a network mirror → Yes (optional)
8. Install GRUB bootloader → Yes

   * Select the disk (usually `/dev/sda`)

### Once installation finishes:

* Remove the ISO from VirtualBox settings (or it will boot into installation again)
* Reboot the VM

---

# 🧪 Part 5: First Boot & Post Installation

## ✅ After Booting:

* Login using the username and password you created
* You’ll be in the **Kali Linux desktop**

## ✅ Optional: Install Guest Additions for Better Experience

1. In VirtualBox menu → Devices → **Insert Guest Additions CD Image**
2. Open terminal in Kali:

```bash
sudo apt update
sudo apt install -y virtualbox-guest-x11
sudo reboot
```

This improves screen resolution, clipboard sharing, and drag & drop.

---

# 📌 Alternative: Use Pre-built Kali Linux VirtualBox Image (Faster Setup)

1. Go to: [https://www.kali.org/get-kali/#kali-virtual-machines](https://www.kali.org/get-kali/#kali-virtual-machines)
2. Download the **Kali Linux VirtualBox image**
3. Extract the `.7z` file using 7-Zip or similar
4. Double-click the `.vbox` file → VirtualBox opens and adds the VM
5. Start the VM — ready to go

---

# 🛡️ Tips for Better Performance & Use

* Enable **2 or more CPUs** in VM Settings → System → Processor
* Increase **Video Memory** (128 MB) in Display settings
* Use **Bridged Adapter** if you need network access outside the VM

