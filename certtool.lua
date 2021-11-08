require("terminal")
require("strutil")
require("filesys")
require("process")
require("stream")
require("time")




KeyStore={}
ExitStatus=0
g_Debug=false

CARootCerts={}
CARootURLs="https://letsencrypt.org/certs/isrgrootx1.pem.txt,https://dl.cacerts.digicert.com/BaltimoreCyberTrustRoot.crt.pem,https://dl.cacerts.digicert.com/CybertrustGlobalRoot.crt.pem,DigiCert Assured ID,https://dl.cacerts.digicert.com/DigiCertAssuredIDRootCA.crt.pem,DigiCert Assured ID G2,https://dl.cacerts.digicert.com/DigiCertAssuredIDRootG2.crt.pem,DigiCert Assured ID G3,https://dl.cacerts.digicert.com/DigiCertAssuredIDRootG3.crt.pem,DigiCert Federated ID,https://dl.cacerts.digicert.com/DigiCertFederatedIDRootCA.crt.pem,DigiCert Global,https://dl.cacerts.digicert.com/DigiCertGlobalRootCA.crt.pem,DigiCert Global G2,https://dl.cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem,DigiCert Global G3,https://dl.cacerts.digicert.com/DigiCertGlobalRootG3.crt.pem,DigiCert High Assurance EV,https://dl.cacerts.digicert.com/DigiCertHighAssuranceEVRootCA.crt.pem,DigiCert Trusted G4,https://dl.cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem,GTE Cybetrust Global,https://dl.cacerts.digicert.com/GTECyberTrustGlobalRoot.crt.pem,Verizon Global,https://dl.cacerts.digicert.com/VerizonGlobalRootCA.crt.pem,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA.pem,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA_G2_ECC.pem,GeoTrust Primary G3,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA_G4_DSA.pem,GeoTrust Primary G4,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA_G4_DSA.pem,GeoTrust Universal,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA.pem,GeoTrust Universal,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA.pem,GeoTrust Universal 2,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA2.pem,GeoTrust Global,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA2.pem,GeoTrust Global 2,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Global_CA2.pem"




function CertDetailsFromCmd(cmd)
local details={}

details.name=cmd.path
details.cert_authority=cmd.cert_authority
details.org=cmd.org
details.location=cmd.location
details.email=cmd.email
details.lifetime=cmd.lifetime

return details
end


function GetCAList()
local Dir, item
local ca_list={}

Dir=filesys.GLOB(WorkingDir.."/*")
item=Dir:next()
while item ~= nil
do
if filesys.exists(item.."/ca.crt") ==true then table.insert(ca_list, item) end
item=Dir:next()
end

return(ca_list)
end



function CmdRead(S)
local str=""
local inchar

inchar=S:getch()
while inchar ~= '\n' and inchar ~= ':'
do
	if string.byte(inchar) == 255 and strutil.strlen(str)==0 then return nil end

	str=str..inchar
	inchar=S:getch()
end

if str==nil then Out:puts("EXIT! str==nil\n") end
Out:flush()

return str
end



function OpenSSLCommand(cmd)
local S, str

if g_Debug == true then print("CMD: "..cmd) end

S=stream.STREAM("cmd:"..cmd, "pty errnull")
S:timeout(3000)
str=CmdRead(S)
while str ~= nil
do
	str=strutil.trim(str)

	if strutil.strlen(str) > 0
	then
		if g_Debug==true then Out:puts(str.."\n") end

		if string.find(str, "Enter pass phrase") ~= nil
		then
		if KeyStore.ca_key == nil then KeyStore.ca_key=UI_AskPassphrase("Enter password for Certificate Authority: ") end 
		S:writeln(KeyStore.ca_key.."\n")
		S:flush()
		end

		if string.find(str, "Enter Import Password") ~= nil
		then
		if KeyStore.cert_key == nil then KeyStore.cert_key=UI_AskPassphrase("Enter password for source certificate: ") end 
		S:writeln(KeyStore.cert_key.."\n")
		S:flush()
		end

		if string.find(str, "Enter Export Password") ~= nil
		then
		if KeyStore.cert_key == nil then KeyStore.cert_key=UI_AskPassphrase("Enter password for new certificate (blank for no passphrase): ") end 
		S:writeln(KeyStore.cert_key.."\n")
		S:flush()
		end

	end

	Out:flush()
	str=CmdRead(S)
end

S:close()
end



function OpenSSLSubject(details)
local str=""

--if email exists, then it must be added first because of some kind of bug in openssl
if strutil.strlen(details.email) > 0 then str=str.."/emailAddress="..details.email end
--name must ALWAYS exist
str=str.."/CN="..details.name
if strutil.strlen(details.country) > 0 then str=str.."/C="..details.country end
if strutil.strlen(details.org) > 0 then str=str.."/O="..details.org end
if strutil.strlen(details.location) > 0 then str=str.."/L="..details.location end

return str
end


function OpenSSLCreateRSAKey()
OpenSSLCommand("openssl genrsa -des3 -out ca.key 2048")
end


function OpenSSLCreateCSR(details)
local subj

subj=OpenSSLSubject(details)
OpenSSLCommand("openssl req -new -newkey rsa:2048 -nodes -subj '" .. subj .. "' -keyout " .. details.name .. ".key -out " .. details.name .. ".csr")
end


function OpenSSLPEMtoPKCS12(outpath, certpath, keypath)
if strutil.strlen(certpath) == 0
then 
print("ERROR: no path given to certificate to import")
elseif strutil.strlen(keypath) == 0
then
print("ERROR: no path given to keyfile to import")
else
OpenSSLCommand("openssl pkcs12 -export -out " .. outpath .. " -inkey " .. keypath .. " -in ".. certpath)
end
end


function OpenSSLPKCS12toPEM(inpath, certpath, keypath)
local str

str=filesys.basename(inpath)
if strutil.strlen(certpath) == 0 then certpath=str..".crt" end
if strutil.strlen(keypath) == 0 then keypath=str..".key"   end

OpenSSLCommand("openssl pkcs12 -nodes -in " .. inpath .. " -out " .. certpath)
OpenSSLCommand("openssl pkcs12 -nodes -nocerts -in " .. inpath .. " -out " .. keypath)
if CheckGenerateFiles(".", {certpath, keypath}, true) == false then ExitStatus=1 end
end



function OpenSSLCreateCA(details)
local str, S

if strutil.strlen(details.name) == 0
then
print("ERROR: No name provided for CA.");
return
end

str=WorkingDir .. details.name .. "/"
filesys.mkdirPath(str)
process.chdir(str)

--initialize serial number (incremented at each operation) to 01
S=stream.STREAM("serial","w")
S:writeln("01\n")
S:close()

--just generate this file
S=stream.STREAM("index.txt","w")
S:close()

OpenSSLCommand("openssl genrsa -des3 -out ca.key 2048")
str=OpenSSLSubject(details)
OpenSSLCommand("openssl req -new -x509 -days 3650 -key ca.key -subj \""..str.."\" -out ca.crt")


if CheckGenerateFiles(WorkingDir .. details.name .. "/", {"ca.crt", "ca.key"}, true ) == false then ExitStatus=1 end
end



function OpenSSLCreateCertificate(details)
local str, path
local csrpath, certpath, keypath, pfxpath

if strutil.strlen(details.name) == 0
then
print("ERROR: No name provided for Certificate. You must provide at least a 'common name' for certificate creation.");
return
end


path=WorkingDir .. details.cert_authority
process.chdir(path)

path=WorkingDir .. details.name .. "/"
filesys.mkdirPath(path)
csrpath=path .. details.name .. ".csr"
certpath=path .. details.name .. ".crt"
keypath=path .. details.name .. ".key"
pfxpath=path .. details.name .. ".pfx"

OpenSSLCommand("openssl genrsa -out ".. path .. details.name..".key 2048")
str="openssl req -new -key ".. keypath .. " -out " .. csrpath .. " -subj \"/CN="..details.name.."\""
OpenSSLCommand(str)

str="openssl x509 -req -days " .. details.lifetime .. " -in ".. csrpath .. " -CA ca.crt -CAkey ca.key -CAserial serial -out " .. certpath
OpenSSLCommand(str)

--str="openssl rsa -in ".. path .. details.name .. ".key -out ".. path .. details.name .. ".key.insecure"
--OpenSSLCommand(str)

OpenSSLPEMtoPKCS12(pfxpath, certpath , keypath)

if CheckGenerateFiles(WorkingDir .. "/" .. details.name, { details.name..".crt", details.name..".key"}, true) == false then ExitStatus=1 end
end



function UI_AskPassphrase(Prompt)
local str

str=Out:prompt(Prompt, "hidetext")
print("\n")

return str
end



function UI_AskCertDetails(details)

if details == nil then details={} end

while strutil.strlen(details.name) == 0 
do
details.name=Out:prompt("Name: ")
Out:puts("\n")

if strutil.strlen(details.name) == 0 then print("\rYou must enter a name for the new item.~>") end
end

if strutil.strlen(details.org) == 0 
then
details.org=Out:prompt("Organization: ")
Out:puts("\n")
end

if strutil.strlen(details.country) == 0 
then
details.country=Out:prompt("Country: ")
Out:puts("\n")
end

if strutil.strlen(details.location) == 0 
then
details.location=Out:prompt("Location: ")
Out:puts("\n")
end

if strutil.strlen(details.email) == 0 
then
details.email=Out:prompt("Email: ")
Out:puts("\n")
end

if strutil.strlen(details.lifetime) == 0 
then
details.lifetime=Out:prompt("Lifetime (days): ")
Out:puts("\n")
end


return details
end



function CheckGenerateFiles(dir, files, output_result)
local path, i, item, str
local retval=false

for i,item in ipairs(files)
do
	if strutil.strlen(dir) then path=dir.."/"..item
	else path=item
	end

	if filesys.size(path) > 0 
	then 
	str=path .. " created okay" 
	retval=true
	elseif filesys.exists(path) == true then str=path .. " zero-length file created"
	else str=path .. " error no file created" 
	end

	if output_result == true then print(str) end
end

return retval
end


function CreateCSR()
local details

details=CertDetailsFromCmd(cmd)
details=UI_AskCertDetails(details)
OpenSSLCreateCSR(details)

end


function CreateCA(cmd)
local details

details=CertDetailsFromCmd(cmd)
details=UI_AskCertDetails(details)
-- details.passphrase=Out:prompt("Security Passphrase: ")
Out:puts("\n")
Out:flush()

OpenSSLCreateCA(details)
end


function ChooseCA(details)

str="Select CA From: "
for i,item in ipairs(GetCAList())
do
str=str..filesys.basename(item).." "
end

print(str)
details.cert_authority=Out:prompt("CA to use: ")
Out:puts("\n")

if CheckGenerateFiles(WorkingDir .. details.cert_authority .. "/", {"ca.crt", "ca.key", "ca.pfx"} ) == false
then
	print("ERROR: No such certification authority '" .. details.cert_authority .. "'")
	details.cert_authority=nil
end

end



function CreateCertificate(cmd)
local details={}
local ca_list, item, i, str

details=CertDetailsFromCmd(cmd)
while details.cert_authority == nil do ChooseCA(details) end
if details.name == nil then details=UI_AskCertDetails(details) end
if details.lifetime==nil or details.lifetime==0 then details.lifetime=365 end

OpenSSLCreateCertificate(details)

end



function CertAuthorityMenu()
local Menu, choice

Out:clear()
Menu=terminal.TERMMENU(Out, 1, 1, Out:width() - 2, Out:length() - 2)
Menu:add("Create New CA", "new")

dirs=filesys.GLOB(WorkingDir.."*")
item=dirs:next()
while item ~= nil
do
	if filesys.exists(item.."/serial")
	then
		Menu:add(filesys.basename(item), item)
	end
item=dirs:next()
end


choice=Menu:run()

if strutil.strlen(choice) > 0
then
	if choice=="new"
	then
	CreateNewCA()
	else
	CreateCertificate(choice)
	end
end

end


function ReformatDate(indate)
local outdate, i, str
local months={"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
local day, mon, year, time;

toks=strutil.TOKENIZER(indate, "\\S")
mon=toks:next()
day=string.format("%02d", tonumber(toks:next()))
time=toks:next()
year=toks:next()

outdate=year.."/"

for i,str in ipairs(months)
do
	if str==mon
	then
		outdate=outdate..string.format("%02d", i).."/"
	end
end

outdate=outdate..day

return outdate, time
end



function ParseIdent(input)
local toks, tok
local ident={}


ident.name=""
ident.country=""
ident.org=""
ident.unit=""

toks=strutil.TOKENIZER(input, ", ")
tok=toks:next()
while tok ~= nil
do
	if string.sub(tok, 1, 2) == "C="
	then
		ident.country=string.sub(tok,3)
	elseif string.sub(tok, 1, 3) == "CN="
	then
		ident.name=string.sub(tok, 4)
	elseif string.sub(tok, 1, 2) == "O="
	then
		ident.org=string.sub(tok, 3)
	elseif string.sub(tok, 1, 2) == "OU="
	then
		ident.unit=string.sub(tok, 4)
	end
tok=toks:next()
end


return ident
end


function ParseIssuer(cert, input)
local ident

ident=ParseIdent(input)
cert.issuer=ident.name
cert.issuer_country=ident.country
cert.issuer_org=ident.org
cert.issuer_unit=ident.unit

if strutil.strlen(cert.issuer)==0 then cert.issuer=ident.org end

end




function ParseSubject(cert, input)
local ident

ident=ParseIdent(input)
cert.subject=ident.name
cert.country=ident.country
cert.org=ident.org
cert.unit=ident.unit

if strutil.strlen(cert.subject)==0 then cert.subject=ident.unit end
if strutil.strlen(cert.subject)==0 then cert.subject=ident.org end
end



function ExaminePEMCertificate(pem)
local S, str
local cert={}

cert.pem=pem
cert.subject=""
cert.org=""
cert.country=""
cert.issuer=""
cert.issuer_org=""
cert.issuer_country=""
cert.start_date=""
cert.end_date=""
cert.start_time=""
cert.end_time=""

S=stream.STREAM("cmd:openssl x509 -text 2>/dev/null", "")
if S ~= nil
then
	S:writeln(cert.pem.."\n")
	str=S:readln()

	while str ~= nil
	do
		str=strutil.trim(str)
		toks=strutil.TOKENIZER(str, ":")
		item=strutil.trim(toks:next())
		value=strutil.trim(toks:remaining())
		if item=="Subject"
		then
		ParseSubject(cert, value)
		elseif item=="Issuer"
		then
		ParseIssuer(cert, value)
		elseif item=="Not Before"
		then
		item=string.gsub(value, "  ", " ")
		cert.start_date,cert.start_time=ReformatDate(item)
		elseif item=="Not After"
		then
		item=string.gsub(value, "  ", " ")
		cert.end_date,cert.end_time=ReformatDate(item)
		end

		str=S:readln()
	end
end


return cert
end



function LoadCertificatesFromStream(S)
local str, cert 
local pem=""
local certs={}

str=S:readln()
while str ~= nil
do
	str=strutil.trim(str)
	str=strutil.trim(str)
	if strutil.strlen(str) > 0
	then
	if str=="-----BEGIN CERTIFICATE-----" 
	then 
	pem=str.."\n"
	elseif str=="-----END CERTIFICATE-----" 
	then
		pem=pem..str.."\n"
		cert=ExaminePEMCertificate(pem)
		table.insert(certs, cert)
	else
	pem=pem..str.."\n"
	end
	end

str=S:readln()
end

return certs
end



function LoadCertificatesFromFile(path)
local S, certs

S=stream.STREAM(path, "r")
if S ~= nil
then
	certs=LoadCertificatesFromStream(S)
	S:close()
else
	io.stderr:write("ERROR: Failed to open '"..path.."'\n")
end

return certs
end


function DisplayCertificateList(certs)
local cert, i, now, diff
local end_date_color=""

now=time.format("%Y/%m/%d")

for i,cert in ipairs(certs)
do
end_date_color=""

if cert.end_date < now 
then 
end_date_color="~r" 
else
end_date_color="~g"
end

Out:puts(cert.start_date .. "-" .. end_date_color .. cert.end_date .. "~0 ~e" .. cert.subject .. "~0 issuer=[" .. cert.issuer .. "/".. cert.issuer_org.."/"..cert.issuer_country.."]\n")
end
end


function GetDuration(secs)
local day, hour, str

hour=3600
day=hour * 24

if secs > day then str=string.format("%0.2f", secs / day) .. " days"
elseif secs > hour then str=string.format("%0.2f", secs / hour) .. " hours"
else str=string.format("%0.2f", secs) .. " seconds" 
end

return str
end




function ListCertificatesFromFile(path)
local certs

certs=LoadCertificatesFromFile(path)
DisplayCertificateList(certs)

end


function ShowCertificatesFromFile(path)
local certs, cert, i, S

certs=LoadCertificatesFromFile(path)
S=stream.STREAM("cmd:openssl x509 -text 2>/dev/null", "")
if S ~= nil
then
for i,cert in ipairs(certs)
do
	S:writeln(cert.pem)
	str=S:readln()
	while str ~= nil
	do
	str=strutil.trim(str)
	print(str)
	str=S:readln()
	end
end
S:close()
end

end


function ProcessCertificatesFromFiles(action, path)
local toks, item

toks=strutil.TOKENIZER(path, ",")
item=toks:next()
while item ~= nil
do
	if strutil.strlen(item) > 0
	then 
		if action=="list" then ListCertificatesFromFile(item) 
		elseif action=="show" then ShowCertificatesFromFile(item)
		end
	end
item=toks:next()
end

end



function BundleAddCerts(S, certs)
local i, cert
for i,cert in ipairs(certs)
do
	S:writeln("## " .. cert.start_date .."-"..cert.end_date.. "  "..cert.subject.." ("..cert.org.." - "..cert.country..")".."\n") 
	S:writeln(cert.pem.."\n")
end
end


function BundleCertificates(cmd)
local toks, item, S, certs, path

print(cmd.path)

S=stream.STREAM(cmd.outpath, "w")
if S ~= nil
then
	toks=strutil.TOKENIZER(cmd.path, ",")
	item=toks:next()
	while item ~= nil
	do
	if strutil.strlen(item) > 0
	then
	certs=LoadCertificatesFromFile(item)
	if certs then BundleAddCerts(S, certs) end
	end

	item=toks:next()
	end
S:close()
end

end



function UnbundleCertificatesFromFile(path)
local certs, cert, i, str

certs=LoadCertificatesFromFile(path)
for i,cert in ipairs(certs)
do
	str=cert.subject
	if strutil.strlen(str) ==0 then str=tostring(i) end
	str=str..".pem"
	S=stream.STREAM(str, "w")
	if S ~= nil
	then
	S:writeln(cert.pem)
	S:close()
	else
	print("ERROR: failed to open"..str)
	end
end

end




function ErrorsInCerts(certs, expire_warn_time)
local i, cert, now, today
local error_text=""
local RetVal=false

today=time.format("%Y/%m/%d")
now=time.secs()

for i,cert in ipairs(certs)
do
	when=time.tosecs("%Y/%m/%dT%H:%M:%S", cert.end_date.."T"..cert.end_time)

	if cert.start_date > today
	then 
	error_text=error_text.."ERROR: Certificate Not Yet Valid: "..cert.subject .. " valid: "..cert.start_date " - "..cert_end_date .."\n"
	end

	if cert.end_date < today then error_text=error_text.."ERROR: Certificate Expired: "..cert.subject .. " valid: "..cert.start_date " - "..cert_end_date .."\n"
	elseif (when - now) < expire_warn_time then error_text=error_text.."WARN: Certificate ".. cert.subject .. " Expires in "..GetDuration(when - now) .. "\n"
	end
end

if strutil.strlen(error_text) > 0 then
print(error_text)
RetVal=true
end

end



function CertificateScrape(Cmd)
local S, Out, certs, toks

if strutil.strlen(Cmd.server_name) == 0
then
	toks=strutil.TOKENIZER(Cmd.path, ":")
	Cmd.server_name=toks:next()
end

S=stream.STREAM("cmd:openssl s_client -showcerts -connect " .. Cmd.path .. " -servername " .. Cmd.server_name, "r innull errnull")
if S ~= nil
then
	certs=LoadCertificatesFromStream(S)
	DisplayCertificateList(certs)

	if Cmd.export_certs == true
	then
	Out=stream.STREAM(Cmd.path..".pem", "w")
	BundleAddCerts(Out, certs)
	Out:close()
	end

	if strutil.strlen(Cmd.mail_errors_to) > 0
	then
	if ErrorsInCerts(certs, Cmd.mail_errors_to, Cmd.warn_time) == true then ExitStatus=1 end
	end

S:close()
end

end


function DrawHelp()
print("certtool.lua [action] [args]")
print()
print("certtool.lua show <path>                                     - show details of certificates in file at <path>")
print("certtool.lua bundle <path 1> ... <path n> -out <outpath>     - bundle certificates listed into a single filei at 'outpath'")
print("certtool.lua unbundle <path>                                 - unbundle certificates out of a single file into a file per certificate")
print("certtool.lua scrape <hostname>:<port>                        - connect to host and print/check certificates it offers")
print("certtool.lua pem2pfx <cert> <key>                            - connect to host and print/check certificates it offers")
print("certtool.lua pfx2pem <path>                                  - unpack pfx file at <path> into pem certificate and key files")
print("certtool.lua ca  <name> <certificate args>                   - create a certificate authority called <name> (if name is ommited ask for fields)")
print("certtool.lua csr <name> <certificate args>                   - create a signing request for a certificate with common-name <name> (if name is ommited ask for fields)")
print("certtool.lua cert <name> <certificate args>                  - create a certificate with common-name <name> (if name is ommited ask for fields)")
print("certtool.lua key <path>                                      - create public key at <path>")
print("certtool.lua --help                                          - this help")
print("certtool.lua -help                                           - this help")
print("certtool.lua -?                                              - this help")
print()
print("<certificate args> are a set of arguments describing the fields within a certificate, signing request or C.A. If none are specified, and no <name> argument is specified then an interactive query mode will be activated to ask for values. The only field that must have a value is 'name'. If interactive query mode is not desired then arguments can be specified on the command-line using:")
print()
print(" -days <n>                   days that certificate will be valid for")
print(" -org  <org name>            organization name")
print(" -location  <location>       location")
print(" -loc  <location>            location")
print(" -country <2-letter code>    2-letter country code")
print(" -cc <2-letter code>         2-letter country code")
print(" -email <address>            contact email address")
print(" -ca <C.A. name>             name of certificate authority to use")
print()
print("Examples:")
print()
print("Show certificate details")
print("  certtool.lua show ./server.crt")
print("Connect to service and output its certificate list")
print("  certtool.lua scrape myserver:443")
print("Bundle certificates into cert_bundle.pem")
print("  certtool.lua bundle -out cert_bundle.pem cert1.pem cert2.pem cert3.pem")
print("Unbundle certificates from cert_bundle.pem into seperate files")
print("  certtool.lua unbundle cert_bundle.pem")
print("Create a certificate authority in interactive mode (asks for needed info)")
print("  certtool.lua ca")
print("Create a certificate authority called 'myCA' with org and email fields set")
print("  certtool.lua ca myCA -org 'My Company' -email webmaster@my.com")
print("Create a certificate signing request in interactive mode")
print("  certtool.lua csr")
print("Create a certificate signing request (to be signed by another CA) for a certificate called 'server_cert'")
print("  certtool.lua csr server_cert")
print("Create a certificate in interactive mode")
print("  certtool.lua cert")
print("Create a certificate called 'server_cert' using C.A. 'myCA'")
print("  certtool.lua cert server_cert -ca myCA")
print("Pack key and certificate into pfx/pkcs12 file")
print("  certtool.lua pem2pfx server_cert.pfx server_cert.crt server_cert.key")
print("Unpack key and certificate from pfx/pkcs12 file")
print("  certtool.lua pfx2pem ./server_cert.pfx")

end



function ParseCommandLine()
local Cmd={}
local i, item, toks

Cmd.path=""
Cmd.outpath="-"
Cmd.mail_errors_to=""
Cmd.warn_time=665 * 24 * 3600

for i,item in ipairs(arg)
do

if strutil.strlen(item) > 0
then
	if i==1
	then 
	Cmd.action=item
	elseif item=="-export"
	then
	Cmd.export_certs=true
	elseif item=="-k" or item=="-key"
	then
	Cmd.key=arg[i+1]
	arg[i+1]=""
	elseif item=="-o" or item=="-out" or item=="-outpath"
	then
	Cmd.outpath=arg[i+1]
	arg[i+1]=""
	elseif item=="-xk" or item=="-outkey"
	then
	Cmd.outkey=arg[i+1]
	arg[i+1]=""
	elseif item=="-days"
	then
	Cmd.lifetime=arg[i+1]
	arg[i+1]=""
	elseif item=="-org"
	then
	Cmd.organization=arg[i+1]
	arg[i+1]=""
	elseif item=="-location" or item=="-loc"
	then
	Cmd.location=arg[i+1]
	arg[i+1]=""
	elseif item=="-country" or item=="-cc"
	then
	Cmd.location=arg[i+1]
	arg[i+1]=""
	elseif item=="-email"
	then
	Cmd.email=arg[i+1]
	arg[i+1]=""
	elseif item=="-ca"
	then
	Cmd.cert_authority=arg[i+1]
	arg[i+1]=""
	elseif item=="-debug"
	then
	g_Debug=true
	elseif item=="-help" or item=="--help" or item=="-?"
	then
	Cmd.action="help"
	elseif strutil.strlen(Cmd.path) > 0 then Cmd.path=Cmd.path..","..item
	else
	Cmd.path=item
	end
end

end



if Cmd.action=="pem2pfx" or Cmd.action=="pfx2pem"
then
	toks=strutil.TOKENIZER(Cmd.path, ',')
	Cmd.outpath=toks:next()
	Cmd.certpath=toks:next()
	Cmd.keypath=toks:next()
end



return Cmd
end




WorkingDir=process.getenv("HOME").."/.cert_mgr/"
Out=terminal.TERM()

--process.lu_set("SSL:VerifyCertFile", "test.pem")

Cmd=ParseCommandLine()
if Cmd.action=="list"
then
ProcessCertificatesFromFiles("list", Cmd.path)
elseif Cmd.action=="show"
then
ProcessCertificatesFromFiles("show", Cmd.path)
elseif Cmd.action=="scrape"
then
CertificateScrape(Cmd)
elseif Cmd.action=="bundle"
then
if strutil.strlen(Cmd.path)==0 then Cmd.path=CARootURLs end
BundleCertificates(Cmd)
elseif Cmd.action=="unbundle"
then
UnbundleCertificatesFromFile(Cmd.path)
elseif Cmd.action=="key"
then
CreateKey(Cmd.path)
elseif Cmd.action=="csr"
then
CreateCSR()
elseif Cmd.action=="ca"
then
CreateCA()
elseif Cmd.action=="cert"
then
CreateCertificate(Cmd)
elseif Cmd.action=="pem2pfx"
then
OpenSSLPEMtoPKCS12(Cmd.outpath, Cmd.certpath, Cmd.keypath)
elseif Cmd.action=="pfx2pem"
then
OpenSSLPKCS12toPEM(Cmd.path, Cmd.certpath, Cmd.keypath)
else
DrawHelp()
end
 
Out:reset()
os.exit(ExitStatus)
