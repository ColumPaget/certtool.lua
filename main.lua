






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


function ShowCertificatesFromFile(path)
local certs, cert, i, S


--openssl req -noout -text -in <CSR_FILE>

certs=LoadCertificatesFromFile(path)
if certs ~= nil
then
for i,cert in ipairs(certs)
do
	S=stream.STREAM("cmd:openssl x509 -text 2>/dev/null", "")
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
	end
	print("")
	print("")
	S:close()
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





WorkingDir=process.getenv("HOME").."/.certtool/"
filesys.mkdir(WorkingDir)
Out=terminal.TERM()

openssl=OpenSSLInit()
local_ca=CertAuthoritiesInit()
ui=UIInit()


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
elseif Cmd.action=="version"
then
print("certtool.lua version "..Version)
else
DrawHelp()
end
 
Out:puts("\n") 
Out:reset()

os.exit(ExitStatus)
