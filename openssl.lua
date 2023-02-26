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


--this handled messages that openssl emits, error messages or 
--password requests
openssl.cmd_process_output=function(self, S, Out, line)
local str

		if g_Debug==true then Out:puts("["..line.."]\n") end

		if string.find(line, "encryption password") ~= nil
		then
		str=ui:askPassphrase(line..":")
		S:writeln(str.."\n")
		S:flush()
		end

		if string.find(line, "decryption password") ~= nil
		then
		str=ui:askPassphrase(line..":")
		S:writeln(str.."\n")
		S:flush()
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
		end

		if string.find(line, "unsupported message digest type") ~= nil
		then
		Out:puts("~e~rERROR:" .. line .."~0\n")
		end


		if line == "bad number of days"
		then
		str=S:readln()
		Out:puts("~e~rERROR: bad lifetime/number of days: "..str.."~0\n")
		end

		if line == "error"
		then 
		str=S:readln()
		Out:puts("~e~rERROR:"..str.."~0\n")
		end
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

		if strutil.strlen(str) > 0 then self:cmd_process_output(S, Out, str) end

		Out:flush()
		str=self:cmdread(S)
	end

	S:close()
else
		Out:puts("~e~rERROR: failed to run openssl command:" .. cmd .. "~0\n")
end

str=process.waitStatus(pid)
if str ~= "exit:0" then Out:puts("~e~rERROR: openssl command exited with status:" .. str .. "~0\n") end

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
self:command(str)

--str="openssl rsa -in ".. path .. details.name .. ".key -out ".. path .. details.name .. ".key.insecure"
--self:command(str)

self:PEMtoPKCS12(pfxpath, certpath , keypath)

return self:check_files(WorkingDir .. "/" .. details.name, { details.name..".crt", details.name..".key"}, true) 
end



return openssl
end
