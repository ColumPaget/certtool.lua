SYNOPSIS
========

Certtool.lua is another tool for doing openssl operations and creating self-signed certificates. It requires libUseful (https://github.com/ColumPaget/libUseful) and libUseful-lua (https://github.com/ColumPaget/libUseful-lua) to be installed.


INSTALL
=======

The program is a single 'certtool.lua' script. However, this is built out of many other .lua files, using 'make'. 'make install' will copy certtool.lua /usr/local/bin.


USAGE
=====

It can either be run as 'lua certtool.lua' or you can use linux's 'binfmt' system to automatically invoke lua to run the script.

```
certtool.lua [action] [args]

certtool.lua list <path>                                     - list certificates in file at <path>
certtool.lua show <path>                                     - show details of certificates in file at <path>
certtool.lua bundle <path 1> ... <path n> -out <outpath>     - bundle certificates listed into a single filei at 'outpath'
certtool.lua unbundle <path>                                 - unbundle certificates out of a single file into a file per certificate
certtool.lua scrape <hostname>:<port>                        - connect to host and print/check certificates it offers
certtool.lua pem2pfx <cert> <key>                            - connect to host and print/check certificates it offers
certtool.lua pfx2pem <path>                                  - unpack pfx file at <path> into pem certificate and key files
certtool.lua ca  <name> <certificate args>                   - create a certificate authority called <name> (if name is ommited ask for fields)
certtool.lua csr <name> <certificate args>                   - create a signing request for a certificate with common-name <name> (if name is ommited ask for fields)
certtool.lua cert <name> <certificate args>                  - create a certificate with common-name <name> (if name is ommited ask for fields)
certtool.lua key <path>                                      - create public key at <path>
certtool.lua --help                                          - this help
certtool.lua -help                                           - this help
certtool.lua -?                                              - this help
```

<certificate args> are a set of arguments describing the fields within a certificate, signing request or C.A. If none are specified, and no <name> argument is specified then an interactive query mode will be activated to ask for values. The only field that must have a value is 'name'. If interactive query mode is not desired then arguments can be specified on the command-line using:

```
 -days <n>                   days that certificate will be valid for
 -org  <org name>            organization name
 -location  <location>       location
 -loc  <location>            location
 -country <2-letter code>    2-letter country code
 -cc <2-letter code>         2-letter country code
 -email <address>            contact email address
 -ca <C.A. name>             name of certificate authority to use
```

EXAMPLES
========


Show certificate details
```
  certtool.lua show ./server.crt
```
Connect to service and output its certificate list
```
  certtool.lua scrape myserver:443
```
Bundle certificates into cert_bundle.pem
```
  certtool.lua bundle -out cert_bundle.pem cert1.pem cert2.pem cert3.pem
```
Unbundle certificates from cert_bundle.pem into seperate files
```
  certtool.lua unbundle cert_bundle.pem
```
Create a certificate authority in interactive mode (asks for needed info)
```
  certtool.lua ca
```
Create a certificate authority called 'myCA' with org and email fields set
```
  certtool.lua ca myCA -org 'My Company' -email webmaster@my.com
```
Create a certificate signing request in interactive mode
```
  certtool.lua csr
```
Create a certificate signing request (to be signed by another CA) for a certificate called 'server_cert'
```
  certtool.lua csr server_cert
```
Create a certificate in interactive mode
```
  certtool.lua cert
```
Create a certificate called 'server_cert' using C.A. 'myCA'
```
  certtool.lua cert server_cert -ca myCA
```
Pack key and certificate into pfx/pkcs12 file
```
  certtool.lua pem2pfx server_cert.pfx server_cert.crt server_cert.key
```
Unpack key and certificate from pfx/pkcs12 file
```
  certtool.lua pfx2pem ./server_cert.pfx
```
