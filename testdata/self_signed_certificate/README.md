
Purpose
-------

This is a self-signed certificate, which is can be used for testing the `keystore-go` library.
It was created by using openssl CLI tool in an interactive terminal session.

Requirements
------------

* OpenSSL 3+ (using 3.3.2 3 Sep 2024 (Library: OpenSSL 3.3.2 3 Sep 2024))


Documentation, how the file were created
----------------------------------------

You need to open a terminal and enter these commands line by line:

```shell
openssl genrsa -out key.pem 4096
openssl req -new > cert.csr
openssl x509 -in cert.csr -out cert.pem -req -signkey key.pem -days 9999
openssl pkcs12 -export -out cert.p12 -in cert.pem -inkey key.pem -passin pass:pass -passout pass:password -nokeys -jdktrust anyExtendedKeyUsage -name test-name -caname test-ca-name
```
When `openssl req ...` asks you for some certificate subject information, enter the following values:

```text
Enter PEM pass phrase:pass
Country Name (2 letter code) [AU]:de
State or Province Name (full name) [Some-State]:Brandenburg
Locality Name (eg, city) []:Potsdam
Organization Name (eg, company) [Internet Widgits Pty Ltd]:keystore-go
Organizational Unit Name (eg, section) []:github.com.pavlo-v-chernykh.keystore-go
Common Name (e.g. server FQDN or YOUR name) []:pavlo-v-chernykh.keystore-go                                                                   
Email Address []:keystore-go@example.org     

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:pass
An optional company name []:
```