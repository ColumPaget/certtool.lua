title: certtool.lua
mansection: 1
date: 20 March 2024

SYNOPSIS
========

certtool.lua is a lua script that aims to simplify certificate creation/management and file encryption with openssl.


USAGE
=====

```
certtool.lua list <path>                                     - list certificates in file at <path>
certtool.lua show <path>                                     - show details of certificates in file at <path>
certtool.lua bundle <path 1> ... <path n> -out <outpath>     - bundle certificates listed into a single filei at 'outpath'
certtool.lua unbundle <path>                                 - unbundle certificates out of a single file into a file per certificate
certtool.lua scrape <hostname>:<port>                        - connect to host and print/check certificates it offers
certtool.lua pem2pfx <cert> <key>                            - convert pem certificate and key files to a single pfx file
certtool.lua pfx2pem <path>                                  - unpack pfx file at <path> into pem certificate and key files
certtool.lua ca  <name> <certificate args>                   - create a certificate authority called <name> (if name is ommited ask for fields)
certtool.lua csr <name> <certificate args>                   - create a signing request for a certificate with common-name <name> (if name is ommited ask for fields)
certtool.lua cert <name> <certificate args>                  - create a certificate with common-name <name> (if name is ommited ask for fields)
certtool.lua key <path>                                      - create public key at <path>
certtool.lua enc <path> <options>                            - encrypt file at <path> with a password
certtool.lua dec <path> <options>                            - decrypt file at <path> with a password
certool.lua zerossl:cert <name> <options>                    - create certificate using zerossl
certool.lua zerossl:list                                     - list zerossl certificates
certool.lua zerossl:show <id>                                - show details of certificate with hash id <id>
certool.lua zerossl:info <id>                                - show details of certificate with hash id <id>
certool.lua zerossl:valid <id>                               - validate a certificate with hash id <id> using 'file' method
certool.lua zerossl:email <id> -email <dest.email>           - validate certificate with hash id <id> by sending email to 'dest.email'
certool.lua zerossl:install <id>                             - install certificate with hash id <id>
certool.lua zerossl:get <id>                                 - get (download) certificate with hash id <id>
certool.lua zerossl:cancel <id>                              - cancel certificate with hash id <id>
certool.lua zerossl:revoke <id>                              - revoke certificate with hash id <id>
certool.lua zerossl:provision                                - create, validate and install a new certificate
certtool.lua --help                                          - this help
certtool.lua -help                                           - this help
certtool.lua -?                                              - this help
```

when creating certificates, the path to an alternative working directory can be provided with '-dir <path>'. The working directory contains both certificate authorities and certificates produced with them, each stored in it's own directory.


OPTIONS
=======

-dir <path>
: path to alternate working directorty to store CAs/certificates in (defaults to ~/.certtool)

-bits <bitsize>
: keysize in bits when creating certificates/certificate-signing-requests

-days <n>
: number of days that certificate will be valid for

-org <org name>
: organization name of certificate

-location  <location>
: organization location of certificate

-loc  <location>
: organization location of certificate

-country <2-letter code>
: organization 2-letter country code of certificate

-cc <2-letter code>
: organization 2-letter country code of certificate

-email <address>
: contact email address of certificate, or email to send validations to (zerossl)

-ca <C.A. name>
: name of certificate authority to use when creating certificates

-copy
: copy details (location, email etc) of certificate from signing C.A.

-out <path>
: set output path for the the `enc` and `dec` commands. Without this certtool.lua will produce output filenames by appending '.enc' to encrypted files and '.dec'. to decrypted files

-o <path>
: set output path for the the `enc` and `dec` commands. Without this certtool.lua will produce output filenames by appending '.enc' to encrypted files and '.dec'. to decrypted files

-algo <algorithm>
: encryption algorithm to use for the enc and dec commands (defaults to aes-256-cbc)

-hash <algorithm>
: hashing/digest algorithm to use (defaults to sha256)

-digest <algorithm>
: hashing/digest algorithm to use (defaults to sha256)

-api <key>
: supply api key for commands (currently zerossl commands) requiring it



ENCRYPT/DECRYPT
===============

The 'enc' and 'dec' commands encrypt and decrypt files using a password. If no output path is specified using '-o' or '-out' then they will create an output file whose name is the name of the input file with either '.enc' or '.dec' appended. They will not overwrite an existing file, even if that filename is suplied with '-out'.




ZEROSSL
=======

The zerossl: commands are somewhat experimental. You must supply your API key using either the -api command-line argument, or by setting an environment variable 'ZEROSSL_API_KEY'. Validation using email has been seen to work, other validation methods are untested


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

