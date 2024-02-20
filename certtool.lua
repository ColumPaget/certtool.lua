require("terminal")
require("strutil")
require("filesys")
require("process")
require("stream")
require("time")



Version="1.3"
KeyStore={}
ExitStatus=0
g_Debug=false

CARootCerts={}
CARootURLs="https://letsencrypt.org/certs/isrgrootx1.pem.txt,https://dl.cacerts.digicert.com/BaltimoreCyberTrustRoot.crt.pem,https://dl.cacerts.digicert.com/CybertrustGlobalRoot.crt.pem,DigiCert Assured ID,https://dl.cacerts.digicert.com/DigiCertAssuredIDRootCA.crt.pem,DigiCert Assured ID G2,https://dl.cacerts.digicert.com/DigiCertAssuredIDRootG2.crt.pem,DigiCert Assured ID G3,https://dl.cacerts.digicert.com/DigiCertAssuredIDRootG3.crt.pem,DigiCert Federated ID,https://dl.cacerts.digicert.com/DigiCertFederatedIDRootCA.crt.pem,DigiCert Global,https://dl.cacerts.digicert.com/DigiCertGlobalRootCA.crt.pem,DigiCert Global G2,https://dl.cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem,DigiCert Global G3,https://dl.cacerts.digicert.com/DigiCertGlobalRootG3.crt.pem,DigiCert High Assurance EV,https://dl.cacerts.digicert.com/DigiCertHighAssuranceEVRootCA.crt.pem,DigiCert Trusted G4,https://dl.cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem,GTE Cybetrust Global,https://dl.cacerts.digicert.com/GTECyberTrustGlobalRoot.crt.pem,Verizon Global,https://dl.cacerts.digicert.com/VerizonGlobalRootCA.crt.pem,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA.pem,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA_G2_ECC.pem,GeoTrust Primary G3,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA_G4_DSA.pem,GeoTrust Primary G4,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA_G4_DSA.pem,GeoTrust Universal,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA.pem,GeoTrust Universal,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA.pem,GeoTrust Universal 2,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA2.pem,GeoTrust Global,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA2.pem,GeoTrust Global 2,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Global_CA2.pem"


function CertDetailsCreate()
local details={}

details.pem=""
details.subject=""
details.name=""
details.alt_names=""
details.org=""
details.country=""
details.location=""
details.email=""
details.issuer=""
details.issuer_org=""
details.issuer_country=""
details.start_date=""
details.end_date=""
details.start_time=""
details.end_time=""
details.lifetime=""


return details
end




function CertDetailsFromCmd(cmd)
local details

details=CertDetailsCreate()
details.name=cmd.path
details.cert_authority=cmd.cert_authority
details.org=cmd.org
details.location=cmd.location
details.email=cmd.email
details.lifetime=cmd.lifetime

return details
end


function OpenSSLInit()
local openssl={}


-- this function checks that the expected .crt and .key files (certificate and public key)
-- exist as expected after an openssl command is run
openssl.check_files=function(self, dir, files, output_result)
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


--this function reads output from openssl. Most of the important output, like
--requests for a password, end with ':'
openssl.cmdread=function(self, S)
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


openssl.cmd_send_password=function(self, S, prompt, pass_count)
local str

	str=ui:askPassphrase(prompt..":")
	S:writeln(str.."\n")
	S:flush()
end


--this handled messages that openssl emits, error messages or 
--password requests
openssl.cmd_process_output=function(self, S, Out, line)
local str
local result=true

		if g_Debug==true then Out:puts("["..line.."]\n") end

		if string.find(line, "encryption password") ~= nil
		then
		openssl:cmd_send_password(S, line)
		end

		if string.find(line, "decryption password") ~= nil
		then
		openssl:cmd_send_password(S, line)
		end


		if string.find(line, "Enter pass phrase") ~= nil
		then
		if KeyStore.ca_key == nil then KeyStore.ca_key=ui:askPassphrase("Enter password for Certificate Authority: ") end 
		S:writeln(KeyStore.ca_key.."\n")
		S:flush()
		end

		if string.find(line, "Enter Import Password") ~= nil
		then
		if KeyStore.cert_key == nil then KeyStore.cert_key=ui:askPassphrase("Enter password for source certificate: ") end 
		S:writeln(KeyStore.cert_key.."\n")
		S:flush()
		end

		if string.find(line, "Enter Export Password") ~= nil
		then
		if KeyStore.cert_key == nil then KeyStore.cert_key=ui:askPassphrase("Enter password for new certificate (blank for no passphrase): ") end 
		S:writeln(KeyStore.cert_key.."\n")
		S:flush()
		end

		if string.find(line, "problems making Certificate Request") ~= nil
		then
		Out:puts(line.."\n")
		result=false
		end

		if string.find(line, "unsupported message digest type") ~= nil
		then
		Out:puts("~e~rERROR:" .. line .."~0\n")
		result=false
		end


		if line == "bad number of days"
		then
		str=S:readln()
		Out:puts("~e~rERROR: bad lifetime/number of days: "..str.."~0\n")
		result=false
		end

		if line == "error"
		then 
		str=S:readln()
		Out:puts("~e~rERROR:"..str.."~0\n")
		result=false
		end

return result
end



--this actually runs an openssl command, and handles any output from it
openssl.command=function(self, cmd)
local S, str, pid

if g_Debug == true then print("CMD: "..cmd) end

S=stream.STREAM("cmd:"..cmd, "pty")
if S ~= nil
then
	S:timeout(3000)
	pid=S:getvalue("PeerPID")
	str=self:cmdread(S)
	while str ~= nil
	do
		str=strutil.trim(str)

		if strutil.strlen(str) > 0 
		then 
			if self:cmd_process_output(S, Out, str) == false 
			then
			 process.kill(pid, process.SIGKILL)
			 break 
			end
		end

		Out:flush()
		str=self:cmdread(S)
	end

	S:close()
else
		Out:puts("~e~rERROR: failed to run openssl command:" .. cmd .. "~0\n")
end

str=process.waitStatus(pid)
if str == "exit:0" then return true end

Out:puts("~e~rERROR: openssl command exited with status:" .. str .. "~0\n") 
return false

end


--make a 'subject' string, which is a string passed to openssl that
--contains all the details (common name, email Address, country, organization)
--that make up a certificate
openssl.mkSubject=function(self, details)
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


--generate an RSAkey file (usually used for CAs)
openssl.mkRSAkey=function(self, path)
self:command("openssl genrsa -des3 -out '" .. path .. "' 2048")
end


--make a certificate signing request for certificate named in 'details.name'
openssl.mkCSR=function(self, details)
local subj, csrfile

csrfile=details.name .. ".csr"
subj=self:mkSubject(details)
self:command("openssl req -new -newkey rsa:2048 -nodes -subj '" .. subj .. "' -keyout " .. details.name .. ".key -out " .. csrfile)

return self:check_files(".", {csrfile}, true)
end


-- export certficates from a PEM file into a PKCS12 format file
openssl.PEMtoPKCS12=function(self, outpath, certpath, keypath)
if strutil.strlen(certpath) == 0
then 
print("ERROR: no path given to certificate to import")
elseif strutil.strlen(keypath) == 0
then
print("ERROR: no path given to keyfile to import")
else
self:command("openssl pkcs12 -export -out " .. outpath .. " -inkey " .. keypath .. " -in ".. certpath)
end
end


-- export certficates from a PKCS12 format to a PEM format file
openssl.PKCS12toPEM=function(self, inpath, certpath, keypath)
local str

str=filesys.basename(inpath)
if strutil.strlen(certpath) == 0 then certpath=str..".crt" end
if strutil.strlen(keypath) == 0 then keypath=str..".key"   end

self:command("openssl pkcs12 -nodes -in " .. inpath .. " -out " .. certpath)
self:command("openssl pkcs12 -nodes -nocerts -in " .. inpath .. " -out " .. keypath)
return self:check_files(".", {certpath, keypath}, true)
end


openssl.encrypt_file=function(self, inpath, outpath, encrypt_details)
local str

str="openssl enc -a -salt -" .. encrypt_details.enc_algo  .. " -md " .. encrypt_details.md_algo .. " -in ".. inpath
if strutil.strlen(outpath) and outpath ~= "-" then str=str .. " -out " .. outpath end
self:command(str)
end


openssl.decrypt_file=function(self, inpath, outpath, encrypt_details)
local str

str="openssl enc -d -a -" .. encrypt_details.enc_algo  .. " -md " .. encrypt_details.md_algo .. " -in ".. inpath
if strutil.strlen(outpath) and outpath ~= "-" then str=str .. " -out " .. outpath end
self:command(str)
end



-- make a CA on disk from 'details'
openssl.mkCA=function(self, details)
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

self:command("openssl genrsa -des3 -out ca.key 2048")
str=self:mkSubject(details)
self:command("openssl req -new -x509 -days 3650 -key ca.key -subj \""..str.."\" -out ca.crt")


return self:check_files(WorkingDir .. details.name .. "/", {"ca.crt", "ca.key"}, true )
end


-- make a certificate
openssl.mkCertificate=function(self, details)
local str, path
local csrpath, certpath, keypath, pfxpath

if strutil.strlen(details.name) == 0
then
	print("ERROR: No name provided for Certificate. You must provide at least a 'common name' for certificate creation.");
	return
end


path=WorkingDir .. details.cert_authority
print("Using CA: "..path)
process.chdir(path)

path=WorkingDir .. details.name .. "/"
filesys.mkdirPath(path)
csrpath=path .. details.name .. ".csr"
certpath=path .. details.name .. ".crt"
keypath=path .. details.name .. ".key"
pfxpath=path .. details.name .. ".pfx"

self:command("openssl genrsa -out ".. path .. details.name..".key 2048")
str="openssl req -new -key ".. keypath .. " -out " .. csrpath .. " -subj \"" .. self:mkSubject(details) .."\""
-- if strutil.strlen(details.alt_names) > 0 then str = str .. " -addext \"subjectAltName=" .. details.alt_names .. "\"" end
self:command(str)

str="openssl x509 -req -days " .. details.lifetime .. " -in ".. csrpath .. " -CA ca.crt -CAkey ca.key -CAserial serial -out " .. certpath
if self:command(str) == true
then
	--str="openssl rsa -in ".. path .. details.name .. ".key -out ".. path .. details.name .. ".key.insecure"
	--self:command(str)

	self:PEMtoPKCS12(pfxpath, certpath , keypath)

	return self:check_files(WorkingDir .. "/" .. details.name, { details.name..".crt", details.name..".key"}, true) 
end

return false
end



return openssl
end

-- Given a subject, which might contain '/emailAddress=' and other cruft,
-- clean it up to get a name
function CertificateSubjectToName(subject)
local toks, str

toks=strutil.TOKENIZER(subject, "/emailAddress")
str=toks:next()
str=string.gsub(str, '/', '_')

if string.sub(str, 1, 5)=="http:"  then str=string.sub(str, 6) end
if string.sub(str, 1, 6)=="https:" then str=string.sub(str, 7) end
return str
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
ident.alt_names=""
ident.org=""
ident.unit=""
ident.location=""
ident.email=""

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
	elseif string.sub(tok, 1, 3) == "OU="
	then
		ident.unit=string.sub(tok, 4)
	elseif string.sub(tok, 1, 2) == "L="
	then
		ident.location=string.sub(tok, 3)
	elseif string.sub(tok, 1, 13) == "emailAddress="
	then
		ident.email=string.sub(tok, 14)
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
cert.issuer_location=ident.location
cert.issuer_email=ident.email

if strutil.strlen(cert.issuer)==0 then cert.issuer=ident.org end

end




function ParseSubject(cert, input)
local ident

ident=ParseIdent(input)
cert.subject=ident.name
cert.location=ident.location
cert.country=ident.country
cert.org=ident.org
cert.unit=ident.unit
cert.email=ident.email

if strutil.strlen(cert.subject)==0 then cert.subject=ident.unit end
if strutil.strlen(cert.subject)==0 then cert.subject=ident.org end
end


function DecodePEMContents(cert, S)
local str

	S:writeln(cert.pem.."\n")
	S:commit()
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


function ExaminePEMCertificate(pem)
local S, str
local cert={}

cert=CertDetailsCreate()
cert.pem=pem
cert.type="crt"

S=stream.STREAM("cmd:openssl x509 -text 2>/dev/null", "")
if S ~= nil then DecodePEMContents(cert, S) end
S:close()

return cert
end


function ExaminePEMCSR(pem)
local S, str
local cert={}

cert=CertDetailsCreate()
cert.pem=pem
cert.type="csr"

S=stream.STREAM("cmd:openssl req -noout -text", "")
if S ~= nil then DecodePEMContents(cert, S) end
S:close()

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
	elseif str=="-----BEGIN_CERTIFICATE REQUEST-----"
	then
	pem=str.."\n"
	elseif str=="-----END CERTIFICATE-----" 
	then
		pem=pem..str.."\n"
		cert=ExaminePEMCertificate(pem)
		table.insert(certs, cert)
	elseif str=="-----END CERTIFICATE REQUEST-----"
	then
		pem=pem..str.."\n"
		cert=ExaminePEMCSR(pem)
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


--this module provides functions that bundle or unbundle multiple certs together into a pem file

--add a cert to a bundle file
function BundleAddCerts(S, certs)
local i, cert, name

for i,cert in ipairs(certs)
do
	name=CertificateSubjectToName(cert.subject)
	S:writeln("## " .. cert.start_date .. "-" .. cert.end_date .. "  " .. name .. " (".. cert.org .. " - " .. cert.country .. ")" .. "\n") 
	S:writeln(cert.pem.."\n")
end
end


--bundle certificates together into a file
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


--unbundle certificates from a file, into individual pem files
function UnbundleCertificatesFromFile(path)
local certs, cert, i, str

certs=LoadCertificatesFromFile(path)
for i,cert in ipairs(certs)
do
  str=CertificateSubjectToName(cert.subject)
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

-- this module relates to local certificate-authorites for self-signed certificates
-- these are stored in ~/.certtool/

function CertAuthoritiesInit()
local CA={}

CA.path=function(self, name)
return WorkingDir .. name .. "/"
end

CA.cert_path=function(self, name)
return WorkingDir .. name .. "/ca.crt"
end

CA.key_path=function(self, name)
return WorkingDir .. name .. "/ca.key"
end


-- get list of currently configured local certificates
CA.list=function(self)
local Dir, item
local ca_list={}

Dir=filesys.GLOB(WorkingDir.."/*")
item=Dir:next()
while item ~= nil
do
if filesys.exists(item.."/ca.crt") == true then table.insert(ca_list, item) end
item=Dir:next()
end

return(ca_list)
end


-- create a new CA on disk
CA.create=function(self, details)

details=ui:askCertDetails(details)
Out:puts("\n")
Out:flush()

if filesys.exists(self:cert_path(details.name)) == true
then
Out:puts("~yWARN: a CA named '"..details.name.."' already exists. Abort?~0\n")
if ui:yesno("") == true then return false end
end

return openssl:mkCA(details)
end


-- chose a CA from the ones that exist already
-- this function offers to create a new one if none exists
CA.choose=function(self, details)
local i, item, ca
local str=""

for i,item in ipairs(self:list())
do
str=str..filesys.basename(item).." "
end

if strutil.strlen(str) == 0
then
	if ui:yesno("No Certificate Authorties. Create a new one?  ") == false then return nil end

	Out:puts("\n~eCreating New Certificate Authority~0\n")
	ca=ui:askCertDetails(nil)
	if ca ~= nil
	then
	openssl:mkCA(ca)
	details.cert_authority=ca.name
	end
end

if strutil.strlen(details.cert_authority) == 0
then
print("Select CA From: " .. str)
details.cert_authority=Out:prompt("CA to use: ")
Out:puts("\n")
end


if strutil.strlen(details.cert_authority) > 0
then
	if openssl:check_files(self:path(details.cert_authority), {"ca.crt", "ca.key", "ca.pfx"} ) == false
	then
		print("ERROR: No such certification authority '" .. details.cert_authority .. "'")
		details.cert_authority=nil
	end
else
	details.cert_authority=nil
end

end


-- get details like organization, local, country etc from a
-- local certificate authority so these can be used in a
-- certificate created by this authority. The idea is that people
-- normally use an authority to create certificates for domains
-- that have the same details as the authority
CA.details=function(self, details)
local ca_cert, certs, cert

certs=LoadCertificatesFromFile(self:cert_path(details.cert_authority))
cert=certs[1]

if strutil.strlen(details.org) ==0 then details.org=cert.org end
if strutil.strlen(details.location) ==0 then details.location=cert.location end
if strutil.strlen(details.country) ==0 then details.country=cert.country end
if strutil.strlen(details.email) ==0 then details.email=cert.email end

return details
end


return CA
end

function UIInit()
local ui={}

ui.yesno=function(self, Prompt)
local chooser

chooser=Out:choice("prompt='"..Prompt.."' choices=yes,no")

if chooser:run() == "yes" then return true end
return false
end


ui.askPassphrase=function(self, Prompt)
local str

str=Out:prompt(Prompt, "hidetext")
print("\n")

return str
end


ui.askCertField=function(self, Prompt, minlen, maxlen, tip)
local str=""
local len

while true
do
str=Out:prompt(Prompt)
Out:puts("\n")

len=strutil.strlen(str)
if ( (len >= minlen) and (len <= maxlen) ) or len == 0 then break end

Out:puts("~r".."ERROR: this field must be " .. tostring(minlen) .. " to " .. tostring(maxlen) .. " characters long. Or it can be left blank.~0\n")
if strutil.strlen(tip) > 0 then Out:puts(tip.."\n") end
end


return str
end



ui.askCertDetails=function(self, details)
local str

if details == nil then details=CertDetailsCreate() end

-- if name and anything else has been supplied, then assume the
-- user just wants to use those items and doesn't need to be 
-- asked for all details
if strutil.strlen(details.name) > 0
then
if strutil.strlen(details.org) > 0 then return details end
if strutil.strlen(details.country) > 0 then return details end
if strutil.strlen(details.location) > 0 then return details end
if strutil.strlen(details.email) > 0 then return details end
end


while strutil.strlen(details.name) == 0 
do
details.name=ui:askCertField("Name: ", 4, 64)
if strutil.strlen(details.name) == 0 then print("\rYou must enter a name for the new item.~>") end
end

--[[
if strutil.strlen(details.alt_names) == 0 
then
details.alt_names=Out:prompt("Alt. Names: ")
Out:puts("\n")
end
]]--

if strutil.strlen(details.org) == 0 
then
details.org=ui:askCertField("Organization: ", 1, 99999999)
end

if strutil.strlen(details.country) == 0 
then
details.country=ui:askCertField("Country: ", 2, 2, "This field should contain the 2-letter country code.")
end

if strutil.strlen(details.location) == 0 
then
details.location=ui:askCertField("Location: ", 1, 99999999)
end

if strutil.strlen(details.email) == 0 
then
details.email=ui:askCertField("Email: ", 1, 99999999)
end

if strutil.strlen(details.lifetime) == 0 
then
  str=ui:askCertField("Lifetime (days): ", 1, 99999999)
  if strutil.strlen(str) == 0 then details.lifetime=365
  else details.lifetime=tonumber(str)
  end
end


return details
end


return ui
end

function DrawHelp()
print("certtool.lua [action] [args]")
print()
print("certtool.lua list <path>                                     - list certificates in file at <path>")
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
print("certtool.lua enc <path> <options>                            - encrypt file at <path> with a password")
print("certtool.lua dec <path> <options>                            - decrypt file at <path> with a password")
print("certtool.lua --help                                          - this help")
print("certtool.lua -help                                           - this help")
print("certtool.lua -?                                              - this help")
print()
print("when creating certificates, the path to an alternative working directory can be provided with '-dir <path>'. The working directory contains both certificate authorities and certificates produced with them, each stored in it's own directory.");
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
print(" -copy                       copy details from certificate of signing C.A.")
print()
print("The 'enc' and 'dec' commands accept the following options/arguments:")
print()
print(" -out <path>          path to encrypted/decrypted output file. Without this certtool.lua will produce output filenames by appending '.enc' to encrypted files and '.dec'. to decrypted files")
print(" -o <path>            path to encrypted/decrypted output file. Without this certtool.lua will produce output filenames by appending '.enc' to encrypted files and '.dec'. to decrypted files")
print(" -algo <algorithm>    encryption algorithm to use (defaults to aes-256-cbc)")
print(" -hash <algorithm>    hashing/digest algorithm to use (defaults to sha256)")
print(" -digest <algorithm>  hashing/digest algorithm to use (defaults to sha256)")
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
Cmd.copy_ca_values=false

for i,item in ipairs(arg)
do

if strutil.strlen(item) > 0
then
	if i==1
	then 
	Cmd.action=item
	elseif item=="-dir"
	then
	WorkingDir=arg[i+1]
	arg[i+1]=""
	elseif item=="-export"
	then
	cmd.export_certs=true
	elseif item=="-k" or item=="-key"
	then
	Cmd.key=arg[i+1]
	arg[i+1]=""
	elseif item=="-o" or item=="-out" or item=="-outpath"
	then
	Cmd.outpath=arg[i+1]
	arg[i+1]=""
	elseif item=="-days"
	then
	Cmd.lifetime=arg[i+1]
	arg[i+1]=""
	elseif item=="-org"
	then
	Cmd.org=arg[i+1]
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
	elseif item=="-copy"
	then
	Cmd.copy_ca_values=true
	elseif item=="-algo"
	then
	Cmd.enc_algo=arg[i+1]
	arg[i+1]=""
	elseif item=="-digest" or item=="-hash"
	then
	Cmd.md_algo=arg[i+1]
	arg[i+1]=""
	elseif item=="-debug"
	then
	g_Debug=true
	elseif strutil.strlen(Cmd.path) > 0 then Cmd.path=Cmd.path..","..item
	else
	Cmd.path=item
	end
end

end


if Cmd.action=="-version" or Cmd.action=="--version" or Cmd.action=="-v"
then
	Cmd.action="version"
elseif Cmd.action=="-help" or Cmd.action=="--help" or Cmd.action=="-?"
then
	Cmd.action="help"
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









function CreateCA(cmd)
local details

details=CertDetailsFromCmd(cmd)
if local_ca:create(details) == true
then 
Out:puts("Certificate Authority: '"..details.name.."' created.\n")
else 
Out:puts("~rERROR: CA creation failed~0\n")
ExitStatus=1
end

end


function CreateCSR(cmd)
local details

details=CertDetailsFromCmd(cmd)
details=ui:askCertDetails(details)
if openssl:mkCSR(details) == true
then 
Out:puts("Signing Request for '"..details.name.."' created.\n")
else 
Out:puts("~rERROR: CSR creation failed~0\n")
ExitStatus=1
end

end


function CreateCertificate(cmd)
local details={}
local ca_list, item, i, str

details=CertDetailsFromCmd(cmd)

if  details.cert_authority == nil then  local_ca:choose(details) end
if  details.cert_authority == nil then  return end

if cmd.copy_ca_values==true then details=local_ca:details(details) end

Out:puts("~eCreate Certificate~0\n")
while strutil.strlen(details.name) == 0 do details=ui:askCertDetails(details) end
if details.lifetime==nil or details.lifetime==0 then details.lifetime=365 end

if openssl:mkCertificate(details) == true 
then 
Out:puts("Certificate for '"..details.name.."' created.\n")
else 
Out:puts("~rERROR: Certificate creation failed~0\n")
ExitStatus=1
end


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
if certs == nil or #certs == 0
then
print("ERROR: no certificates loaded");
else
DisplayCertificateList(certs)
end

end



function ShowCertificateLaunchOpenssl(cert)
local S

if strutil.strlen(cert.pem) ==0 then return nil end

if cert.type=="crt" then S=stream.STREAM("cmd:openssl x509 -text 2>/dev/null", "")
elseif cert.type=="csr" then S=stream.STREAM("cmd:openssl req -noout -text 2>/dev/null", "")
end

return S
end


function ShowCertificatesFromFile(path)
local certs, cert, i, S

certs=LoadCertificatesFromFile(path)
if certs ~= nil
then
for i,cert in ipairs(certs)
do
	S=ShowCertificateLaunchOpenssl(cert)
	if S ~= nil
	then
		S:writeln(cert.pem)
		Out:puts("~eCERTIFICATE " .. tostring(i) .. "   " .. cert.subject .. "~0\n")
		str=S:readln()
		while str ~= nil
		do
			str=strutil.trim(str)
			print(str)
			str=S:readln()
		end
	S:close()
	end
	print("")
	print("")
end
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

if strutil.strlen(error_text) > 0
then
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


function EncryptFile(Cmd)
local details={}

outpath=filesys.basename(Cmd.path) .. ".enc"
details.enc_algo="aes-256-cbc"
details.md_algo="sha256"

if strutil.strlen(Cmd.enc_algo) > 0 then details.enc_algo=Cmd.enc_algo end
if strutil.strlen(Cmd.md_algo) > 0 then details.md_algo=Cmd.md_algo end
if strutil.strlen(Cmd.outpath) > 0 then outpath=Cmd.outpath end
openssl:encrypt_file(Cmd.path, outpath, details)
end

function DecryptFile(Cmd)
local details={}
local outpath

outpath=filesys.basename(Cmd.path) .. ".dec"

details.enc_algo="aes-256-cbc"
details.md_algo="sha256"

if strutil.strlen(Cmd.enc_algo) > 0 then details.enc_algo=Cmd.enc_algo end
if strutil.strlen(Cmd.md_algo) > 0 then details.md_algo=Cmd.md_algo end
if strutil.strlen(Cmd.outpath) > 0 then outpath=Cmd.outpath end
openssl:decrypt_file(Cmd.path, outpath, details)
end


--set default working dir
WorkingDir=process.getenv("HOME").."/.certtool/"
--parse command line
Cmd=ParseCommandLine()
--make sure working dir ends with a slash. We must do this after ParseCommandLine
--because command-line args can change WorkingDir
WorkingDir=filesys.pathaddslash(WorkingDir)

filesys.mkdir(WorkingDir)
Out=terminal.TERM()

openssl=OpenSSLInit()
local_ca=CertAuthoritiesInit()
ui=UIInit()


--process.lu_set("SSL:VerifyCertFile", "test.pem")


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
CreateCSR(Cmd)
elseif Cmd.action=="ca"
then
CreateCA(Cmd)
elseif Cmd.action=="cert"
then
CreateCertificate(Cmd)
elseif Cmd.action=="pem2pfx"
then
openssl:PEMtoPKCS12(Cmd.outpath, Cmd.certpath, Cmd.keypath)
elseif Cmd.action=="pfx2pem"
then
openssl:PKCS12toPEM(Cmd.path, Cmd.certpath, Cmd.keypath)
elseif Cmd.action=="enc" or Cmd.action=="encrypt"
then
EncryptFile(Cmd)
elseif Cmd.action=="dec" or Cmd.action=="decrypt"
then
DecryptFile(Cmd)
elseif Cmd.action=="version"
then
print("certtool.lua version "..Version)
else
DrawHelp()
end
 
Out:puts("\n") 
Out:reset()

os.exit(ExitStatus)
