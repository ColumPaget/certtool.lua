PREFIX=/usr/local

all:
	cat common.lua cert_details.lua openssl.lua pem_certificate.lua bundle.lua ca.lua ui.lua help.lua command_line.lua main.lua > certtool.lua
	chmod a+x certtool.lua

install:
	-mkdir -p $(PREFIX)/bin
	cp certtool.lua $(PREFIX)/bin
	-mkdir -p $(PREFIX)/share/man/man1
	cp certtool.lua.1 $(PREFIX)/share/man/man1/
