all:
	cat common.lua cert_details.lua openssl.lua pem_certificate.lua bundle.lua ca.lua ui.lua help.lua command_line.lua main.lua > certtool.lua
	chmod a+x certtool.lua

install:
	cp certtool.lua /usr/local/bin
