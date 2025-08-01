Basic Linux Commands - Kali Linux

1. File and Directory Navigation

pwd → shows the current directory you're in

ls → lists the files in the current directory

ls -l → detailed list (long format)

ls -a → shows hidden files too

cd → change directory

cd /home/kali → goes to a specific path

cd .. → moves one directory up

cd ~ → goes back to the home directory

2. File and Directory Management

mkdir foldername → creates a new directory

touch file.txt → creates an empty file

cp source destination → copies a file

ex: cp file.txt backup.txt

mv old.txt new.txt → renames or moves a file

rm file.txt → deletes a file

rm -r foldername → deletes a folder and everything inside it

3. Viewing File Contents

cat file.txt → displays the whole file at once

less file.txt → lets you scroll through file (q to quit)

more file.txt → similar to less, but older

head file.txt → shows first 10 lines

head -n 5 file.txt → shows first 5 lines

tail file.txt → shows last 10 lines

tail -n 20 file.txt → shows last 20 lines

4. Searching for Files and Content

find / -name file.txt → searches entire system for the file (can take time)

grep "text" filename → searches for "text" inside the file

locate filename → quickly finds files (uses a database, may need sudo updatedb first)

which commandname → shows the full path of a command (like which python)

5. Permissions and Ownership

ls -l → shows permissions on files (like rwxr-xr-x)

chmod 755 script.sh → changes permissions

chown user:group file.txt → changes owner of a file

6. Installing Packages (Using apt)

sudo apt update → updates the package list (from the internet)

sudo apt upgrade → upgrades all installed packages

sudo apt install packagename → installs a package

ex: sudo apt install nmap

sudo apt remove packagename → removes a package

7. System Info / User Info

whoami → shows current user

id → shows user ID and group info

uname -a → shows system info (kernel, OS)

top → shows running processes (press q to quit)

df -h → shows disk space usage in human-readable format

free -h → shows memory usage (RAM)

8. Sudo and Root Access

sudo → runs a command as root/superuser

ex: sudo apt update

su → switches to root user (you’ll need root password)

Extra Notes / Tips

Press Tab to auto-complete commands and file names

Use Up/Down arrow keys to scroll through previous commands

Use man command to open the manual for a command

ex: man ls

press q to quit the manual
