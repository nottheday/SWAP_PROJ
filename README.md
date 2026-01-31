---------------------------------------How to make the Website Secure-------------------------------

Step 1: On C:\xammp\apache\conf\, create a ssl folder

Step 2: Go to notepad, copy these contents inside below --- line:
----------------------------------------------
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req

[dn]
C=SG
ST=Singapore
L=Singapore
O=AMC
OU=IT
CN=localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1


Step3: CTRL + S and you will be prompted where to save the file.
Step 4: Go to C:\xampp\apache/conf/ssl
Step 5: Save filename as openssl-san.cnf and select All file types.

Step 6: Go to command prompt and run these commands:
---------------------------------------------------
cd C:\xampp\apache\bin
openssl req -x509 -nodes -days 825 -newkey rsa:2048 -keyout C:\xampp\apache\conf\ssl\localhost.key -out C:\xampp\apache\conf\ssl\localhost.crt -config C:\xampp\apache\conf\ssl\openssl-san.cnf

Step 7: To use the certs generated, edit C:\xampp\apache\conf\extra\httpd-ssl.conf in notepad.

Step 8: CTRL + F and search for SSLCertificateFile.
        You will see #SSLCertificateFile.
        Create a new line without # and type SSLCertificateFile "conf/ssl/localhost.crt"

Step 9: CTRL + F and search for SSLCertificateKey
        You will see #SSLCertificateKeyFile
        Create a new line without # and type SSLCertificateKeyFile "conf/ssl/localhost.key"

Step 10: CTRL + F and search for ServerName
         You will see ServerName www.example.com:443
         Add a comment infront of it.
         Should be #ServerName www.example.com:443
         Add a new line below and type ServerName localhost:443

Step 11: CTRL + S to save the file


Step 12 — Install the certificate into Trusted Root
Go to:
C:\xampp\apache\conf\ssl\localhost.crt

Double click it → Install Certificate

Choose: ✅ Local Machine
(not Current User)

Choose: Place all certificates in the following store

Select: ✅ Trusted Root Certification Authorities

Finish



