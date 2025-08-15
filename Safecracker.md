Link: https://app.hackthebox.com/sherlocks/Safecracker/play

This is the "**insane**" level sherlock task with category "**Malware Analysis**" from "Hack The Box" cybersecurity platform.

Description:
`We recently hired some contractors to continue the development of our Backup services hosted on a Windows server. We have provided the contractors with accounts for our domain. When our system administrator recently logged on, we found some pretty critical files encrypted and a note left by the attackers. We suspect we have been ransomwared. We want to understand how this attack happened via a full in-depth analysis of any malicious files out of our standard triage. A word of warning, our tooling didn't pick up any of the actions carried out - this could be advanced.`

## First look
According to the description we have the triage of Windows Server system after ransomware activity, which must be thoroughly analyzed and answers to the questions provided.

Let's download 1 GB size file in attachment, unarchive and look what's inside:

![[Pasted image 20250619174655.png]]
Okay, in "Uploads" directory is a dump of physical memory:

![[Pasted image 20250619174920.png]]

Actually, there is a lot of artifacts to go through:

![[Pasted image 20250619175423.png]]

In "results" folder the traces of **Kape**, forensics artifact collection utility, are seen:

![[Pasted image 20250619175653.png]]

Time to investigate what has happened.

## Filesystem investigation
First question is:
**Which user account was utilized for initial access to our company server?**

So, now I have to look at forensics artifacts, I guess.
User account and initial access may be found in logs I think, but I will just start by casually walking through users directories.

![[Pasted image 20250619181714.png]]

.NET v4.5 user folders don't have any personal files, so let's leave them for now.
In the folder of user "Administrator" there are 2 interesting folders: "Backups" and "Downloads".

![[Pasted image 20250619182003.png]]

In "Backups"  there are suspicious files with `.31337` and `.note` extensions:

![[Pasted image 20250619182229.png]]
Contents of the first "note" file look like this:
```
You have been hacked by Cybergang31337

Please can you deposit $200,000 in BTC to the following address:
-   16ftSEQ4ctQFDtVZiUBusQUjRrGhM3JYwe

Once you have done so please email: decryption@cybergang31337.hacker
indicating your source BTC address and we will confirm and release decryption keys.

Regards
	-Cybergang31337

```

Thus, file extension `.31337` must be the encrypted version of original file.
This will help me answer the third and 17-th questions:
Q3: **How many files have been encrypted by the the ransomware deployment?**
Q17: **What file extension does the ransomware rename files to?**
Answer: **.31337**

There is a BTC address so Q18 can be answered too.
Answer to Q18: **16ftSEQ4ctQFDtVZiUBusQUjRrGhM3JYwe**

Even more weird the contents of "Downloads" folder:

![[Pasted image 20250619182631.png]]
How Windows Defender executable ended up here?
I need to check it on VirusTotal or something similar.
This is undetected but has **ELF64** format and not **PE64**.

![[Pasted image 20250619183005.png]]

Moreover, no relation to the Windows Defender or Microsoft in "Details" section at all.
I suppose this is a malware, but I will check it a little bit later.

At the file path `..\WinServer-Collection\uploads\auto\C%3A\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` is a powershell command line history file of "Administrator" user.
Contents:
```
wsl --install
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install firefox -y
choco install filezilla -y
choco install filezilla.server
netstat -nao
gpupdate /force
wsl --list -v
wsl --set-version Ubuntu-20.04 2
wsl --install
wsl --set-version Ubuntu-20.04 2
wsl --set-version Ubuntu 2
wsl -l -v
wsl --set-version Ubuntu-22.04 2
wsl -l 0v
wsl -l -v
wsl --set-default-version 2
wsl --list-online
wsl --list --online
wsl --install
wsl --set-default-version 2
wsl --set-version Ubuntu-22.04 2
wsl --set-version Ubuntu-20.04 2
wsl --list --online
wsl --set-version Ubuntu-20.04
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
wsl --set-version Ubuntu-20.04
wsl -l -v
wslconfig.exe /u Ubuntu
wsl -l -v
wsl --install
wslconfig /l
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
wsl --install
wsl
wsl --install
wsl --install -d Ubuntu-20.04
wslconfig /l
wsl -l -v
wsl --install -d Ubuntu-20.04 2
wsl -l -o
wslconfig.exe /u Ubuntu
wsl -l -v
wslconfig.exe /u Ubuntu-20.04
wsl -l -v
wsl --install -d Ubuntu 2
wsl --install -d Ubuntu 
wsl -l -v
wslconfig.exe /u Ubuntu
wsl --set-default-version 2
ping 1.1.1.1
ipconfig
wsl --install#
wsl --install
wsl --install -d Ubuntu
wsreset.exe
net stop wuauserv
net start wuauserv
wsl --install -d Ubuntu
wsl --install -d Debian
reboot now
wsl --install
wsl --install -d Ubuntu
wsl --install -d Ubuntu-20.04
wsl
winget uninstall
wsl --list
wsl --install
wsl --install -d Ubuntu-22.04
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
wsl --install -d Ubuntu-22.04
wsl
wsl --install -d Ubuntu-22.04
wsl
wsl -l -v
```

WSL has been installed and configured with Ubuntu 22.04 inside. Nothing scary here.

In **contractor01** user directory I also stumbled upon powershell command line history file:

![[Pasted image 20250619183341.png]]

Here it is:

```
ubuntu
whoami
net user
net group
net groups
cd ../../
cd .\Users\contractor01\Contacts\
ls
cd .\PSTools\
ls
.\PsExec64.exe -s -i cmd.exe
```

Command `ubuntu` means, that the WSL has been started with Ubuntu Linux distribution previously configured by "Administrator".
Aside the reconnaissance commands, the `PsExec` with `-s` flag executing `cmd.exe` runs shell under SYSTEM account. This is not normal at all so user **contractor01** must be compromised.
Answer to the Q1 is: **contractor01**

Second question:
**Which command did the TA utilize to escalate to SYSTEM after the initial compromise?**
Answer: **.\PsExec64.exe -s -i cmd.exe**

Checked everything and there are no more executable files except **MsMpEng.exe**.
Let's count encrypted files by parsing **$MFT** file with **MFTECmd** tool, then move on to analyzing the executable.

![[Pasted image 20250619204515.png]]

Show all files with that extension:

![[Pasted image 20250619213235.png]]

There are 33 of them.
Answer to Q3: **33**

## Malware analysis

Basic static analysis is the first thing that I should do.
Let's open the binary in **DiE (Detect It Easy)** program:

![[Pasted image 20250624173210.png]]

Going further, I need to check if binary is packed or not.
Strings mostly look like gibberish but there are some related to crypto:

![[Pasted image 20250624173625.png]]

Entropy level is very high:

![[Pasted image 20250624174017.png]]

Imported libraries are only the basic ones:

![[Pasted image 20250624174357.png]]

**libdl.so.2** - library with functions, that provide dynamic linking facilities. **libc.so.6** - linux C library.

But there are function names (`.dynsym` section) related to network interaction such as `connect`, `getaddrinfo`, `socket` and etc.
![[Pasted image 20250624182512.png]]

By the way, question #16 requires to look at `.comment` section, so here we go:

![[Pasted image 20250624173333.png]]

Q16: **What is the contents of the `.comment` section?**
Answer: **GCC: (Debian 10.2.1-6) 10.2.1 20210110**

GCC is the compiler, so answer to Q14 is **gcc**.

Talking about packer, I am leaning towards the option, that It was actually used, but still need to check the binary in IDA.

### Reverse engineering

Starting with the `main()` function, I stumble upon the `memfd_create()`call, from where the name of `memoryfd` is asked in Q8.

![[Pasted image 20250628122558.png]]

Answer to Q8: **test**

By the way, function `memfd_create` creates an anonymous file and returns a file
descriptor which can be used to create memory mappings using the `mmap` function. The file behaves like a regular file, and so can be modified, truncated, memory-mapped, and so on. However, unlike a regular file, it lives in RAM and has a volatile backing storage.

Definition: `int memfd_create (const char *name, unsigned int flags)`

Then, I have found one function, that uses `crypto/evp/evp_enc.c` string as an argument, and by searching on the internet, it is related to OpenSSL (https://github.com/openssl/openssl/blob/master/crypto/evp/evp_enc.c):

![[Pasted image 20250624215946.png]]

More to that, there is an error message in some function about OpenSSL:

![[Pasted image 20250624221357.png]]

So, I guess the cryptography algorithms used in malware are from the OpenSSL library.

The first function in `main()` after `malloc()`\`s is full of OpenSSL functions. I named it respectively, but not precisely, because it requires too much time to go through and understand what's happening. One thing for sure is the data decryption phase. There are 32 and 16 bytes strings transformed and then sent into the abyss of mathematical operations.
32 bytes fits the key size and 16 bytes is IV. It's gotta be AES-256... but what mode?

![[Pasted image 20250628152027.png]]

Q7: **What was the encryption key and IV for the packer?**
Answer: **a5f41376d435dc6c61ef9ddf2c4a9543c7d68ec746e690fe391bf1604362742f:95e61ead02c32dab646478048203fd0b**

Moreover, the **DiE** tool with signature search points at it:

![[Pasted image 20250628155818.png]]

Before I get to the encryption modes, let's finish superficially inspecting the `main()` function.

After OpenSSL initialization and decryption, the decompression follows, and it looks like **zlib** is used:

![[Pasted image 20250628151449.png]]

![[Pasted image 20250628151520.png]]

![[Pasted image 20250628151535.png]]

![[Pasted image 20250628151618.png]]

![[Pasted image 20250628151408.png]]

Q10: **What compression library was used to compress the packed binary?**
Answer: **zlib**

Past function with compression stuff there is a function that executes some functions from the array, which comes from compression function:

![[Pasted image 20250628154918.png]]

![[Pasted image 20250628155015.png]]

Further, plain binary contents are written to the anonymous file 'test', then buffer with decompressed contents is freed:

![[Pasted image 20250628161449.png]]

At last, the malware starts the extracted binary from the memory (by referring to the `/proc` filesystem) with process name as `PROGRAM`:

![[Pasted image 20250628162342.png]]

Q4: **What is the name of the process that the unpacked executable runs as?**
Answer: **PROGRAM**

Now, let's get back to the AES and bruteforce the encryption modes.
First, extract the binary blob at address `0x2893a0` (`0x2883a0` physical offset in the file):

![[Pasted image 20250628170634.png]]

Size is 1637173 (0x18fb40).

I will use **Binary Refinery** (https://github.com/binref/refinery/) tool to extract data from the binary:

![[Pasted image 20250629121903.png]]

Then decrypt and inflate it in **CyberChef**:

![[Pasted image 20250629121947.png]]

Here we can see the start of the ELF header.
Looks like like the CBC mode is the right one and everything decrypted and decompressed correctly:

![[Pasted image 20250629122753.png]]

![[Pasted image 20250629122813.png]]

![[Pasted image 20250629122949.png]]

Q6: **What encryption was the packer using?**
Answer: **AES-256-CBC**

There is a **libpthread** library used, which provides means to manage threads, and multithreading is usual for filesystem encryption programs.
Another interesting thing here is `inet_pton` function in the symbol table. It's utilized for converting IP addresses.

Looking at strings, there are a lot of them and in clear text, so this is the final executable file, I suppose.

![[Pasted image 20250702100226.png]]

But I managed to find some of them in unreadable form. Maybe be there is some decoding/decryption technique will be used, even blowfish, judging by string above.

![[Pasted image 20250702100512.png]]

As usual, let's start inspecting and marking up the binary from the entry point (function `start`), which leads straight to the `main()` function:

![[Pasted image 20250702101333.png]]

![[Pasted image 20250704061813.png]]

First function refers to debugging the program and exception handling. I have marked it a little bit but it is not really needed, because binary is not stripped at all:

![[Pasted image 20250704050140.png]]

Going inside one function which I called `mw_get_tracer_pid()`, we see that `TracerPid` value of the current process is being read:

![[Pasted image 20250704050329.png]]

If the process is being debugged, then that value is not 0 and string "\*\*\*\*\*\*\*DEBUGGED\*\*\*\*\*\*\*\*" is printed.
Thus, we can answer 11-th, 15-th, 19-th questions:
Q11: **The binary appears to check for a debugger, what file does it check to achieve this?**
Answer: **/proc/self/status**
Q15: **If the malware detects a debugger, what string is printed to the screen?**
Answer: **\*\*\*\*\*\*\*DEBUGGED\*\*\*\*\*\*\*\***
Q19: **What string does the binary look for when looking for a debugger?**
Answer: **TracerPid**

Returning back, if debugger is not detected, then **SIGSEGV** handle action is changed to nothing:

![[Pasted image 20250704061117.png]]

![[Pasted image 20250703142528.png]]

And later there is a function that actually raises this exception:

![[Pasted image 20250704064201.png]]

Q12: **What exception does the binary raise?**
Answer: **SIGSEGV**

Further on, second function takes some string looking like a key - "daV324982S3bh2".

![[Pasted image 20250704062042.png]]
But inside is only memory manipulation stuff that doesn't look meaningful.
Moreover, in disassembler listing it doesn't take those args in registers so then to use in function:

![[Pasted image 20250704063843.png]]

After that one function takes encrypted-like data as an argument:

![[Pasted image 20250704064835.png]]

And inside is a function that XORes data:

![[Pasted image 20250704064615.png]]

Marked up version:

![[Pasted image 20250704181201.png]]

Then goes another XOR function:

![[Pasted image 20250704080327.png]]

![[Pasted image 20250704080152.png]]
Finally it uses the key defined at the start and not bytes from encrypted data itself like in the first case.

Marked up version:

![[Pasted image 20250704170456.png]]

Q5: **What is the XOR key used for the encrypted strings?**
Answer: **daV324982S3bh2**

Next function takes directory path `/mnt/c/Users` as an argument:

![[Pasted image 20250704174027.png]]

It recursively reads every file inside that directory, decrypts string array and tries to match decrypted string and filename. Matches are placed into other array.

![[Pasted image 20250704174046.png]]

Q9: **What was the target directory for the ransomware?**
Answer: **/mnt/c/Users**

For Q21 - **What system call is utilized by the binary to list the files within the targeted directories?** - the system call is needed for the function `readdir`, which actually lists files from the directory.
By searching on the net: "On Linux (and many other Unix-like systems), the primary system call utilized by `readdir()` to list directory entries is `getdents (or its 64-bit variant, getdents64)`".
So, the answer is **getdents64**.

Last function to inspect is gotta be a function with file encryption and ransomware functionality.

At the end of it is the snippet to delete original files:

![[Pasted image 20250705201302.png]]

And from Linux manual page we get the answer to the 22nd question:
![[Pasted image 20250705201504.png]]

Q22: **Which system call is used to delete the original files?**
Answer: **unlink**

Searching through the strings I find home directory of some user named "blitztide":

![[Pasted image 20250705205114.png]]

Q20: **It appears that the attacker has bought the malware strain from another hacker, what is their handle?**
Answer: **blitztide**

Malware is for linux and linux doesn't use PE files, so it must be **.exe** extension, which is not targeted by the malware.

Q13: **Out of this list, what extension is not targeted by the malware? `.pptx,.pdf,.tar.gz,.tar,.zip,.exe,.mp4,.mp3`**
Answer: **.exe**