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
