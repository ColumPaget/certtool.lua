require("terminal")
require("strutil")
require("filesys")
require("process")
require("stream")
require("time")
require("dataparser")



Version="2.1"
KeyStore={}
ExitStatus=0
g_Debug=false

CARootCerts={}
CARootURLs="https://letsencrypt.org/certs/isrgrootx1.pem.txt,https://dl.cacerts.digicert.com/BaltimoreCyberTrustRoot.crt.pem,https://dl.cacerts.digicert.com/CybertrustGlobalRoot.crt.pem,DigiCert Assured ID,https://dl.cacerts.digicert.com/DigiCertAssuredIDRootCA.crt.pem,DigiCert Assured ID G2,https://dl.cacerts.digicert.com/DigiCertAssuredIDRootG2.crt.pem,DigiCert Assured ID G3,https://dl.cacerts.digicert.com/DigiCertAssuredIDRootG3.crt.pem,DigiCert Federated ID,https://dl.cacerts.digicert.com/DigiCertFederatedIDRootCA.crt.pem,DigiCert Global,https://dl.cacerts.digicert.com/DigiCertGlobalRootCA.crt.pem,DigiCert Global G2,https://dl.cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem,DigiCert Global G3,https://dl.cacerts.digicert.com/DigiCertGlobalRootG3.crt.pem,DigiCert High Assurance EV,https://dl.cacerts.digicert.com/DigiCertHighAssuranceEVRootCA.crt.pem,DigiCert Trusted G4,https://dl.cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem,GTE Cybetrust Global,https://dl.cacerts.digicert.com/GTECyberTrustGlobalRoot.crt.pem,Verizon Global,https://dl.cacerts.digicert.com/VerizonGlobalRootCA.crt.pem,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA.pem,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA_G2_ECC.pem,GeoTrust Primary G3,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA_G4_DSA.pem,GeoTrust Primary G4,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA_G4_DSA.pem,GeoTrust Universal,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA.pem,GeoTrust Universal,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA.pem,GeoTrust Universal 2,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA2.pem,GeoTrust Global,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA2.pem,GeoTrust Global 2,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Global_CA2.pem"


-- make an outpuath path, potentially relative to 'dir'
-- if no output path given, or path == "-" then return "-", so data goes to standard out
-- this function should only be used with data that can be sent to stdout
function mkoutpath(path, dir)
if strutil.strlen(path) == 0 then outpath="-"
elseif path=="-" then outpath=path
else
  if strutil.strlen(dir) > 0 then outpath=dir .. "/" .. path
  else outpath=path
  end
end

return outpath
end

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
details.bitswide=cmd.bitswide
details.outpath=cmd.outpath

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
openssl.cmd_process_output=function(self, S, Out, line, ctx)
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


		if string.find(line, "Enter pass phrase") ~= nil or string.find(line, "Enter PEM pass phrase") ~= nil
		then

		if KeyStore.ca_key == nil 
		then 
		str=""
		if ctx ~= nil then str=ctx.cert_authority end
		KeyStore.ca_key=ui:askPassphrase("Enter password for Certificate Authority: ", local_ca:get_pass_hint(str))
		if ctx ~= nil and ctx.action=="mkCA" then ui:askPassphraseHint("Enter hint for passphrase (blank for no hint): ", ctx) end
		end 

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
openssl.command=function(self, cmd, ctx)
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
			if self:cmd_process_output(S, Out, str, ctx) == false 
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

details.finalpath=details.name .. ".csr"
subj=self:mkSubject(details)
self:command("openssl req -new -newkey rsa:2048 -nodes -subj '" .. subj .. "' -keyout " .. details.name .. ".key -out " .. details.finalpath)

return self:check_files(".", {details.finalpath}, true)
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
self:command("openssl pkcs12 -export -out " .. mkoutpath(outpath) .. " -inkey " .. keypath .. " -in ".. certpath)
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
str=str .. " -out " .. outpath
self:command(str)
end


openssl.decrypt_file=function(self, inpath, outpath, encrypt_details)
local str

str="openssl enc -d -a -" .. encrypt_details.enc_algo  .. " -md " .. encrypt_details.md_algo .. " -in ".. inpath
str=str .. " -out " .. outpath
self:command(str)
end


openssl.createCAConfig=function(self, details, path)
local S

--generate config file for new CA
S=stream.STREAM(path,"w")
if S ~= nil
then
S:writeln("[ ca ]\ndefault_ca="..details.name.."\n\n")
S:writeln("[ "..details.name.." ]\n")
S:writeln("dir="..ca_dir.."\n")
S:writeln("certs=$dir\n")
S:writeln("crl_dir=$dir\n")
S:writeln("new_certs_dir=$dir\n")
S:writeln("database=$dir/index.txt\n")
S:writeln("serial=$dir/serial\n")
S:writeln("private_key=$dir/ca.key\n")
S:writeln("certificate=$dir/ca.crt\n")
S:writeln("crlnumber=$dir/crlnumber\n")
S:writeln("crl=$dir/ca.crl\n")
S:writeln("default_crl_days=30\n")
S:writeln("default_md=sha256\n")
S:close()
end

end


-- make a CA on disk from 'details'
openssl.mkCA=function(self, details)
local str, S, ca_dir

if strutil.strlen(details.name) == 0
then
	print("ERROR: No name provided for CA.");
	return
end

details.action="mkCA"
ca_dir=WorkingDir .. details.name .. "/"
filesys.mkdirPath(ca_dir)
process.chdir(ca_dir)

--initialize serial number (incremented at each operation) to 01. Must have even number of hex digits.
S=stream.STREAM("serial","w")
S:writeln("01\n")
S:close()

--initialize crl number (incremented at each operation) to 01. Must have even number of hex digits.
S=stream.STREAM("crlnumber","w")
S:writeln("01\n")
S:close()

self:createCAConfig(details, "ca.conf")

--just generate this file, it's a database file that holds a list of created/revoked 
--certificates. It will be empty to start with
S=stream.STREAM("index.txt","w")
S:close()


self:command("openssl genrsa -des3 -out ca.key 2048", details)
str=self:mkSubject(details)
self:command("openssl req -new -x509 -days 3650 -key ca.key -subj \""..str.."\" -out ca.crt", details)


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

self:command("openssl genrsa -out ".. path .. details.name..".key " .. details.bitswide)
str="openssl req -new -key ".. keypath .. " -out " .. csrpath .. " -subj \"" .. self:mkSubject(details) .."\""
-- if strutil.strlen(details.alt_names) > 0 then str = str .. " -addext \"subjectAltName=" .. details.alt_names .. "\"" end
self:command(str)

str="openssl x509 -req" 
str=str .. " -days " .. details.lifetime .. " -in ".. csrpath .. " -CA ca.crt -CAkey ca.key -CAserial serial -out " .. certpath

if self:command(str, details) == true
then
	--str="openssl rsa -in ".. path .. details.name .. ".key -out ".. path .. details.name .. ".key.insecure"
	--self:command(str)

	self:PEMtoPKCS12(pfxpath, certpath , keypath)

	return self:check_files(WorkingDir .. "/" .. details.name, { details.name..".crt", details.name..".key"}, true) 
end

return false
end




openssl.generateCRL=function(self, details)
local str
local ca_dir, ca_conf, ca_cert, ca_key

ca_dir=WorkingDir .. details.cert_authority .. "/"
ca_conf=ca_dir.."ca.conf"
ca_crt=ca_dir.."ca.crt"
ca_key=ca_dir.."ca.key"

if strutil.strlen(details.outpath) == 0 then  details.outpath=details.cert_authority .. ".crl" end

print("Using CA: ".. ca_dir)
str="openssl ca -name " .. details.cert_authority .. " -config " .. ca_conf .. " -gencrl -keyfile ".. ca_key .. " -cert " .. ca_crt .. " -out " .. details.outpath

if details.lifetime > 0 then str=str .. " -crldays " ..details.lifetime end


print("CMD: " .. str)
if self:command(str, details) == true
then
return true
end

return false


end


openssl.CAIndexParse=function(self, line)
local cert={}
local toks, tok, str, i, len

toks=strutil.TOKENIZER(line, "\\S")
cert.state=toks:next()
toks:next()
toks:next()

cert.serial=""
str=toks:next()
str=string.lower(str)
len=strutil.strlen(str)

for i = 1,len,2
do
if i > 1 then cert.serial=cert.serial .. ":" end
cert.serial=cert.serial .. string.sub(str, i, i+1)
end

cert.subject=toks:next()

return cert
end


openssl.certificateIsRevoked=function(self, ca_name, serial)
local ca_dir, S, str, item
local result=false

ca_dir=WorkingDir .. ca_name

S=stream.STREAM(ca_dir .. "/index.txt")
if S ~= nil
then
  str=S:readln()
  while str ~= nil
  do
    str=strutil.trim(str)
    cert=openssl:CAIndexParse(str)
    if cert.state == "R" and cert.serial == serial 
    then
    result=true
    break
    end
    
    str=S:readln()
  end
  S:close()
end

return result
end


-- revoke a certificate
openssl.revokeCertificate=function(self, details)
local str, path, S
local ca_conf, ca_cert, ca_key, ca_crlnumber

if strutil.strlen(details.name) == 0
then
	print("ERROR: No path provided for certificate to revoke.");
	return
end

if strutil.strlen(details.cert_authority) == 0
then
	print("ERROR: No C.A. name provided. Revocation details are stored against a certificate authority.");
	return
end



path=WorkingDir .. details.cert_authority.."/"
print("Using CA: "..path)

ca_conf=path.."ca.conf"
ca_crt=path.."ca.crt"
ca_key=path.."ca.key"
ca_crlnumber=path.."crlnumber"

if filesys.exists(ca_conf) ~= true then self:createCAConfig(details, ca_conf) end
if filesys.exists(ca_crlnumber) ~= true 
then 
S=stream.STREAM(ca_crlnumber, "w")
S:writeln("01\n")
S:close()
end


if self:command("openssl ca -revoke ".. details.name .. " -config " .. ca_conf) == true
then
return true
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

function ParseIdentItem(item, ident)
local toks, tok, key, value

toks=strutil.TOKENIZER(item, "=");
key=strutil.trim(toks:next())
value=strutil.trim(toks:remaining())

if key == "C" then ident.country=value
elseif key == "CN" then ident.name=value
elseif key == "O" then ident.org=value
elseif key == "OU" then ident.unit=value
elseif key == "L" then ident.location=value
elseif key == "emailAddress=" then ident.email=value
end

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
ParseIdentItem(tok, ident)
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
		elseif item=="Serial Number"
		then
		str=S:readln()
		cert.serial=strutil.trim(str);
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

S=stream.STREAM(mkoutpath(cmd.outpath), "w")
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

CA.get_pass_hint=function(self, name)
local S, str

if strutil.strlen(name)==0 then return("") end

S=stream.STREAM(self:path(name) .. "/passhint.txt", "r") 
if S == nil then return("") end
str=S:readdoc()
S:close()

return(str)
end


CA.set_pass_hint=function(self, name, hint)
local S, str

S=stream.STREAM(self:path(name) .. "/passhint.txt", "w")
if S == nil then return(false) end
S:writeln(hint)
S:close()

return(true)
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
local chooser, str

chooser=Out:choice("prompt='"..Prompt.."' choices=yes,no")
str=chooser:run()
print()

if str == "yes" then return true end
return false
end


ui.askPassphrase=function(self, Prompt, hint)
local str

if strutil.strlen(hint) > 0 then print("passphrase hint: " .. hint) end
str=Out:prompt(Prompt, "startext")
print("\n")

return str
end

ui.askPassphraseHint=function(self, Prompt, ctx)
local str

str=Out:prompt(Prompt)
if strutil.strlen(str) > 0 then local_ca:set_pass_hint(ctx.name, str) end
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
  if strutil.strlen(str) > 0 then details.lifetime=tonumber(str) end
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
print("certtool.lua pem2pfx <cert> <key>                            - convert pem certificate and key files to a single pfx file")
print("certtool.lua pfx2pem <path>                                  - unpack pfx file at <path> into pem certificate and key files")
print("certtool.lua ca  <name> <certificate args>                   - create a certificate authority called <name> (if name is ommited ask for fields)")
print("certtool.lua csr <name> <certificate args>                   - create a signing request for a certificate with common-name <name> (if name is ommited ask for fields)")
print("certtool.lua cert <name> <certificate args>                  - create a certificate with common-name <name> (if name is ommited ask for fields)")
print("certtool.lua key <path>                                      - create public key at <path>")
print("certtool.lua revoke <path> -ca <ca name>                     - revoke certificate in file at <path> that was created by C.A. <ca name>")
print("certtool.lua crl -ca <ca name> -o <path>                     - create a certificate revocation list at <path> for C.A. <ca name>")
print("certtool.lua enc <path> <options>                            - encrypt file at <path> with a password")
print("certtool.lua dec <path> <options>                            - decrypt file at <path> with a password")
print("certool.lua zerossl:cert <name> <options>                    - create certificate using zerossl")
print("certool.lua zerossl:list                                     - list zerossl certificates")
print("certool.lua zerossl:show <id>                                - show details of certificate with hash id <id>")
print("certool.lua zerossl:info <id>                                - show details of certificate with hash id <id>")
print("certool.lua zerossl:valid <id>                               - validate a certificate with hash id <id> using 'file' method")
print("certool.lua zerossl:email <id> -email <dest.email>           - validate certificate with hash id <id> by sending email to 'dest.email'")
print("certool.lua zerossl:install <id>                             - install certificate with hash id <id>")
print("certool.lua zerossl:get <id>                                 - get (download) certificate with hash id <id>")
print("certool.lua zerossl:cancel <id>                              - cancel certificate with hash id <id>")
print("certool.lua zerossl:revoke <id>                              - revoke certificate with hash id <id>")
print("certool.lua zerossl:provision                                - create, validate and install a new certificate")
print("certtool.lua --help                                          - this help")
print("certtool.lua -help                                           - this help")
print("certtool.lua -?                                              - this help")
print()
print("when creating certificates, the path to an alternative working directory can be provided with '-dir <path>'. The working directory contains both certificate authorities and certificates produced with them, each stored in it's own directory.");
print()
print("revoking certificates is a two-step process. First you revoke the certificate in a C.A.'s database, then you produce a Certificate Revocation List (CRL) of all revoked certificates for a C.A. that you can supply to programs to inform them of revoked certificates.");
print()
print("The zerossl: commands are somewhat experimental. You must supply your API key using either the -api command-line argument, or by setting an environment variable 'ZEROSSL_API_KEY'. Validation using email has been seen to work, other validation methods are untested")
print()
print("OPTIONS")
print(" -bits <n>                   bitwidth of certificate key, defaults to 2048")
print(" -days <n>                   days that certificate will be valid for")
print(" -org  <org name>            organization name")
print(" -location  <location>       location")
print(" -loc  <location>            location")
print(" -country <2-letter code>    2-letter country code")
print(" -cc <2-letter code>         2-letter country code")
print(" -email <address>            certificate email, or email to send validations to (zerossl)")
print(" -ca <C.A. name>             name of certificate authority to use")
print(" -copy                       copy details from certificate of signing C.A.")
print(" -api <key>                  supply api key for commands (currently zerossl commands) requiring it")
print(" -out <path>                 output path for encrypt, decrypt and zerossl:get commands")
print(" -o <path>                   output path for encrypt, decrypt and zerossl:get commands")
print(" -algo <algorithm>           encryption algorithm to use for encrypt/decrypt command (defaults to aes-256-cbc)")
print(" -hash <algorithm>           hashing/digest algorithm to use for encrypt/decrypt command (defaults to sha256)")
print(" -digest <algorithm>         hashing/digest algorithm to use for encrypt/decrypt command (defaults to sha256)")
print()
print("<certificate args> are a set of arguments describing the fields within a certificate, signing request or C.A. If none are specified, and no <name> argument is specified then an interactive query mode will be activated to ask for values. The only field that must have a value is 'name'. If interactive query mode is not desired then arguments can be specified on the command-line using:")
print()
print(" -bits <n>                   bitwidth of certificate key, defaults to 2048")
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
print("")
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
Cmd.outpath=""
Cmd.mail_errors_to=""
Cmd.warn_time=665 * 24 * 3600
Cmd.copy_ca_values=false
Cmd.bitswide=2048
Cmd.lifetime=365

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
	elseif item=="-bits"
	then
	Cmd.bitswide=arg[i+1]
	arg[i+1]=""
	elseif item=="-api"
	then
	Cmd.apikey=arg[i+1]
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


zerossl={



zerossl_output_error=function(self, P)
local ecode, etype, einfo

if P:value("success") == "1" then Out:puts("~gsuccess~0\n")
else
ecode=P:value("error/code") 

etype=P:value("error/type")
if etype==nil then etype="" end
if etype=="null" then etype="" end


einfo=P:value("error/info")
if einfo==nil then einfo="" end
if einfo=="null" then einfo="" end

Out:puts("~rERROR:~0 " .. ecode .. " - " .. etype .. " " .. einfo .. "\n")
end

end,


--handle generic json responses coming back as
--replies to our API calls
zerossl_handle_result_json=function(self, json)
local P

-- {"success":false,"error":{"code":103,"type":"invalid_api_function","info":"This API Function does not exist."}}

print("JSON: " .. str)
P=dataparser.PARSER("json", str)
self:zerossl_output_error(P)
end,


csr_read=function(self, path)
local S 
local str=""

print("CSR_READ: " .. path)
S=stream.STREAM(path, "r");
if S ~= nil
then
str=S:readdoc()
S:close()
end

str=string.gsub(str, "\n", "\\n")
return str
end,


-- output details
output_details=function(self, item)
local common_name

-- {"id":"d16a8b8adf8e4b9396a603f69a35e205","type":"1","common_name":"mx.columpaget.name","additional_domains":"","created":"2024-05-15 11:35:36","expires":"2024-08-13 00:00:00","status":"draft","validation_type":null,"validation_emails":null,"replacement_for":"","validation":{"email_validation":{"mx.columpaget.name":["admin@mx.columpaget.name","administrator@mx.columpaget.name","hostmaster@mx.columpaget.name","postmaster@mx.columpaget.name","webmaster@mx.columpaget.name","admin@columpaget.name","administrator@columpaget.name","hostmaster@columpaget.name","postmaster@columpaget.name","webmaster@columpaget.name"]},"other_methods":{"mx.columpaget.name":{"file_validation_url_http":"http:\/\/mx.columpaget.name\/.well-known\/pki-validation\/19988E8C931C05FE4EF918E34BAB1B7D.txt","file_validation_url_https":"https:\/\/mx.columpaget.name\/.well-known\/pki-validation\/19988E8C931C05FE4EF918E34BAB1B7D.txt","file_validation_content":["5B33DB2C50B4BB23652B81594CDCF7F2A31F750C83BD727DE4E3A9906540701C","comodoca.com","5eaa5aaeebbea27"],"cname_validation_p1":"_19988E8C931C05FE4EF918E34BAB1B7D.mx.columpaget.name","cname_validation_p2":"5B33DB2C50B4BB23652B81594CDCF7F2.A31F750C83BD727DE4E3A9906540701C.5eaa5aaeebbea27.comodoca.com"}}}}

common_name=item:value("common_name")
print("ID: ".. item:value("id"))
print("Common Name: ".. common_name)
print("Additional Domains: "..item:value("additional_domains"))
print("Created: "..item:value("created"))
print("Expires: "..item:value("expires"))
print("Status: "..item:value("status"))
print("Validation Emails: " .. self:get_validation_emails(item))
print("Validation CNAME P1: " .. item:value("validation/other_methods/"..common_name.."/cname_validation_p1"))
print("Validation CNAME P2: " .. item:value("validation/other_methods/"..common_name.."/cname_validation_p2"))
print("Validation file url http: " .. item:value("validation/other_methods/"..common_name.."/file_validation_url_http"))
print("Validation file url https: " .. item:value("validation/other_methods/"..common_name.."/file_validation_url_https"))

end,


output_cert=function(self, cmd, req_id)
local item

item=self:get_certificate_details(cmd, req_id)
if item == nil then print("ERROR: no such certificate")
else self:output_details(item)
end
end,


new_cert=function(self, cmd)
local csr, str, json, S
local dir

if strutil.strlen(cmd.apikey) == 0 then print("ERROR: no api key supplied"); return; end

cmd.outpath=WorkingDir .."/zerossl/(name)/"
csr=CreateCSR(cmd)

print("CSR created at "..csr.finalpath)

json="{ \"certificate_domains\": \"" .. csr.name  .. "\",\n"
json=json ..  "\"certificate_csr\": \"" .. self:csr_read(csr.finalpath) .. "\""
json=json.."}"

--print("JS:" .. json)

str="https://api.zerossl.com/certificates?access_key=" .. cmd.apikey
S=stream.STREAM(str, "w Content-type=application/json Content-length=" .. tostring(strutil.strlen(json)))
S:writeln(json)
--print(json)
S:commit()
str=S:readdoc()
P=dataparser.PARSER("json", str)
self:output_details(P)

if P ~= nil then return(P:value("id")) end
end,


get_certs_list=function(self, cmd)
local str, S, P

if strutil.strlen(cmd.apikey) == 0 then print("ERROR: no api key supplied"); return; end

str="https://api.zerossl.com/certificates?access_key=" .. cmd.apikey
S=stream.STREAM(str, "r")
if S ~= nil
then
str=S:readdoc()
S:close()
end

P=dataparser.PARSER("json", str)
return(P)
end,




list_cert=function(self, item)
local common_name, str, Now
local status, expires

Now=time.secs()
common_name=item:value("common_name")
status=item:value("status");
if status == "expired" then status = "~r" .. status .."~0"
elseif status == "cancelled" then status = "~r" .. status .."~0"
elseif status == "issued" then status = "~g" .. status .."~0"
elseif status == "draft" then status = "~b" .. status .."~0"
elseif status == "pending_validation" then status = "~e" .. status .."~0"
end

expires=item:value("expires")
if time.tosecs("%Y/%m/%d %H:%M:%S", expires) < Now then expires="~r" .. expires .. "~0" end

str="~e" .. item:value("id") .. "~0 " .. item:value("created") .. " to " .. expires .. "  ~m" .. common_name .. "~0 " .. status 


Out:puts(str.."~0\n")
end,


list_certs=function(self, cmd)
local P, certs, item, str, common_name, emails

P=self:get_certs_list(cmd)
if P ~= nil
then
certs=P:open("results")
item=certs:next()
while item ~= nil
do
common_name=item:value("common_name")
if strutil.strlen(cmd.path) == 0 or common_name == cmd.path then self:list_cert(item) end
item=certs:next()
end
end

end,


--saves an array where each member is a line of text
save_text_array=function(self, fname, contents)
local S, line

S=stream.STREAM(fname, "w")
if (S)
then
  line=contents:next()
  while line ~= nil
  do
    S:writeln(line:value() .. "\n")
    line=contents:next()
  end
else
  Out:puts("~rERROR~0: can't open "..fname.." for writing\n")
end

S:close()
end,


email_validation=function(self, cmd, req_id)
local P, certs, item, common_name, id, emails, str

if strutil.strlen(cmd.apikey) == 0 then print("ERROR: no api key supplied"); return; end
if strutil.strlen(cmd.email) == 0 then print("ERROR: no destination email supplied. Use '-email' to indicate email address."); return; end

item=self:get_certificate_details(cmd, req_id)
common_name=item:value("common_name")
id=item:value("id")
emails=item:open("validation/email_validation/"..common_name)

if strutil.strlen(cmd.email) then json="{\"validation_method\": \"EMAIL\", \"validation_email\": \"" .. cmd.email .."\"}";
else json="{\"validation_method\": \"EMAIL\", \"validation_email\": \"" .. emails:next():value() .."\"}";
end

str="https://api.zerossl.com/certificates/" .. id .. "/challenges?access_key=" .. cmd.apikey
S=stream.STREAM(str, "w Content-type=application/json Content-length=" .. tostring(strutil.strlen(json)))
if S ~= nil
then
S:writeln(json)
S:commit()
str=S:readdoc()
P=dataparser.PARSER("json", str)
if P:value("status") == "pending_validation" then Out:puts("~gOKAY~0: email sent, certificate pending validation\n");
else self:zerossl_output_error(P)
end
S:close()
end

end,


validation_get_file=function(self, item, outpath)
local validation, common_name, fname, path, str, contents

common_name=item:value("common_name")
validation=item:open("validation/other_methods/"..common_name)

--contents=validation:open("file_validation_content")
contents=item:open("validation/other_methods/"..common_name.."/file_validation_content")

fname=filesys.basename(validation:value("file_validation_url_http"))

if strutil.strlen(outpath) == 0 then path=fname
--elseif filesys.filetype(outpath) == "directory" then path=outpath .."/"..fname
else path=outpath
end

self:save_text_array(path, contents)

str="Validation file for: " .. common_name .. " is " .. filesys.basename(path) .. ". This must be made available at: " ..  strutil.unQuote(validation:value("file_validation_url_http")) .. " or " .. strutil.unQuote(validation:value("file_validation_url_https"))
print(str)
end,


validation_file=function(self, cmd, req_id)
local P, certs, item, common_name, validation, str

P=self:get_certs_list(cmd)
certs=P:open("results")
item=certs:next()
while item ~= nil
do
common_name=item:value("common_name")
if strutil.strlen(req_id) == 0 or item:value("id") == req_id or common_name == req_id then self:validation_get_file(item, cmd.outpath) end
item=certs:next()
end

end,


save_certfile=function(self, savename, data)
local str, S

str=strutil.unQuote(data)
S=stream.STREAM(savename, "w")
if S ~= nil
then
print("save to: ".. savename)
S:writeln(str)
S:close()
else
Out:puts("~rERROR~0: failed to open " .. savename .." for writing\n")
end

end,



get_certificate_files=function(self, cmd, id, common_name)
local S, P, str, dir


if strutil.strlen(cmd.apikey) == 0 then print("ERROR: no api key supplied"); return; end

if strutil.strlen(cmd.outpath) > 0 then dir=cmd.outpath .."/"
else dir=""
end

str="https://api.zerossl.com/certificates/" .. id .. "/download/return?access_key=" .. cmd.apikey
S=stream.STREAM(str)
if S ~= nil
then
str=S:readdoc()
P=dataparser.PARSER("json", str)
S:close()
end

if P ~= nil
then
   if P:value("success") == "false" then self:zerossl_output_error(P)
   else
     self:save_certfile(dir .. common_name .. ".crt", P:value("certificate.crt") )
     self:save_certfile(dir .. common_name .. ".ca", P:value("ca_bundle.crt") )

     str=P:value("certificate.crt") .. "\n" ..  P:value("ca_bundle.crt")
     self:save_certfile(dir .. common_name .. "-full.crt", str)
   end
end

end,


get_certificate_details=function(self, cmd, req_id)
local P, certs, item, common_name

P=self:get_certs_list(cmd)
certs=P:open("results")
item=certs:next()
while item ~= nil
do
common_name=item:value("common_name")
id=item:value("id")

if strutil.strlen(req_id) > 0 and id == req_id then return(item)
elseif strutil.strlen(cmd.path) == 0 or common_name == cmd.path then return(item) 
end

item=certs:next()
end

return(nil)
end,


get_id=function(self, cmd)
local item

item=self:get_certificate_details(cmd, cmd.path)
if item ~= nil then return(item:value("id")) end
return nil
end,


get_validation_emails=function(self, item)
local emails, em, common_name
local str=""

common_name=item:value("common_name")
emails=item:open("validation/email_validation/" .. common_name)
if emails ~= nil
then
em=emails:next()
while em ~= nil
do
str=str .. em:value() .. ","
em=emails:next()
end 
else
str=str .. item:value("validation_emails")
end

return(str)
end,




get_certificates=function(self, cmd)
local P, certs, item, common_name

-- don't use 'self:get_certificate' because maybe we are pulling more than one!
P=self:get_certs_list(cmd)

  certs=P:open("results")
  item=certs:next()
  while item ~= nil
  do
    common_name=item:value("common_name")
    id=item:value("id")
    if strutil.strlen(cmd.path) == 0 or id == cmd.path or common_name == cmd.path then self:get_certificate_files(cmd, id, common_name) end
    item=certs:next()
  end

end,


install=function(self, cmd, req_id)
local item, common_name, path

item=self:get_certificate_details(cmd, req_id)
if item ~= nil
then
  common_name=item:value("common_name")
  if strutil.strlen(cmd.outpath) > 0 
  then 
    filesys.mkdirPath(cmd.outpath .. "/")
    self:get_certificate_files(cmd, item:value("id"), common_name)
    path=WorkingDir .."/zerossl/" .. common_name .. "/" .. common_name .. ".key"
    filesys.copy(path, cmd.outpath.."/"..common_name .. ".key")
  end
end
end,


provision=function(self, cmd)
local id

id=self:new_cert(cmd)
self:email_validation(cmd, id)
self:install(cmd, id)
end,



cancel=function(self, cmd, req_id)
if strutil.strlen(cmd.apikey) == 0 then print("ERROR: no api key supplied"); return; end


str="https://api.zerossl.com/certificates/" .. req_id .."/cancel?access_key=" .. cmd.apikey
S=stream.STREAM(str, "w")
S:commit()
str=S:readdoc()
self:zerossl_handle_result_json(str)

end,

revoke=function(self, cmd)
if strutil.strlen(cmd.apikey) == 0 then print("ERROR: no api key supplied"); return; end


str="https://api.zerossl.com/certificates/".. req_id .."/revoke?access_key=" .. cmd.apikey
S=stream.STREAM(str, "w")
S:commit()
str=S:readdoc()
self:zerossl_handle_result_json(str)

end

}







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

return details
end


function CreateCSR(cmd)
local details

details=CertDetailsFromCmd(cmd)
details=ui:askCertDetails(details)
details.outpath=cmd.outpath

if openssl:mkCSR(details) == true
then 
Out:puts("Signing Request for '"..details.name.."' created.\n")
else 
Out:puts("~rERROR: CSR creation failed~0\n")
ExitStatus=1
end

return details
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



function ExportCRL(cmd)
local details={}
local ca_list, item, i, str

details=CertDetailsFromCmd(cmd)

if  details.cert_authority == nil then  local_ca:choose(details) end
if  details.cert_authority == nil then  return end

if openssl:generateCRL(details) == true 
then 
Out:puts("Certificate Revokation List for ".. details.cert_authority.. " created.\n")
else 
Out:puts("~rERROR: CRL export failed~0\n")
ExitStatus=1
end


end


function RevokeCertificate(cmd)
local details={}
local ca_list, item, i, str, certs, cert
local revoked=false

details=CertDetailsFromCmd(cmd)

if  details.cert_authority == nil then  local_ca:choose(details) end
if  details.cert_authority == nil then  return end


certs=LoadCertificatesFromFile(details.name)

if #certs > 1
then
    Out:puts("~rERROR: file '"..details.name.."' contains more than one certificate~0\n")
    ExitStatus=1
else
  for i,cert in ipairs(certs)
  do
  if openssl:certificateIsRevoked(details.cert_authority, cert.serial) == true then revoked=true end
  end
  
  if revoked == true
  then
    Out:puts("Certificate '" .. details.name .. "' is already revoked.\n")
    elseif openssl:revokeCertificate(details) == true 
    then 
    Out:puts("Certificate '" .. details.name .. "' revoked.\n")
    else 
    Out:puts("~rERROR: Certificate revocation failed~0\n")
    ExitStatus=1
  end
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


function EncryptSetup(Cmd, path_suffix)
local details={}
local outpath

outpath=filesys.basename(Cmd.path) .. path_suffix
details.enc_algo="aes-256-cbc"
details.md_algo="sha256"

if strutil.strlen(Cmd.enc_algo) > 0 then details.enc_algo=Cmd.enc_algo end
if strutil.strlen(Cmd.md_algo) > 0 then details.md_algo=Cmd.md_algo end

if strutil.strlen(Cmd.outpath) > 0 
then 
  if Cmd.outpath == "-"
  then
	Out:puts("~rERROR~0: encryption/decryption data cannot be sent to stdout, sorry.\n")
	os.exit(1)
  end
outpath=Cmd.outpath 
end

if filesys.exists(outpath) == true
then
	Out:puts("~rERROR~0: destination file '"..outpath.."' exists! Will not overwrite!\n")
	os.exit(1)
end

return details, outpath
end


function EncryptFile(Cmd)
local details, outpath

details,outpath=EncryptSetup(Cmd, ".enc")
openssl:encrypt_file(Cmd.path, outpath, details)
end

function DecryptFile(Cmd)
local details, outpath

details,outpath=EncryptSetup(Cmd, ".dec")
openssl:decrypt_file(Cmd.path, outpath, details)
end


--set default working dir
WorkingDir=process.getenv("HOME").."/.certtool/"
--parse command line
Cmd=ParseCommandLine()
if strutil.strlen(Cmd.apikey)==0 then Cmd.apikey=process.getenv("ZEROSSL_API_KEY")  end

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
elseif Cmd.action=="revoke"
then
RevokeCertificate(Cmd)
elseif Cmd.action=="crl"
then
ExportCRL(Cmd)
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
elseif Cmd.action=="zerossl:cert"
then
zerossl:new_cert(Cmd)
elseif Cmd.action=="zerossl:list"
then
zerossl:list_certs(Cmd)
elseif Cmd.action=="zerossl:show"
then
zerossl:output_cert(Cmd, Cmd.path)
elseif Cmd.action=="zerossl:info"
then
zerossl:output_cert(Cmd, Cmd.path)
elseif Cmd.action=="zerossl:valid"
then
zerossl:validation_file(Cmd, Cmd.path)
elseif Cmd.action=="zerossl:email"
then
zerossl:email_validation(Cmd, Cmd.path)
elseif Cmd.action=="zerossl:get"
then
zerossl:get_certificates(Cmd, Cmd.path)
elseif Cmd.action=="zerossl:install"
then
zerossl:install(Cmd, Cmd.path)
elseif Cmd.action=="zerossl:provision"
then
zerossl:provision(Cmd)
elseif Cmd.action=="zerossl:cancel"
then
zerossl:cancel(Cmd, Cmd.path)
elseif Cmd.action=="zerossl:revoke"
then
zerossl:revoke(Cmd, Cmd.path)
elseif Cmd.action=="version"
then
print("certtool.lua version "..Version)
else
DrawHelp()
end
 
Out:puts("\n") 
Out:reset()

os.exit(ExitStatus)
