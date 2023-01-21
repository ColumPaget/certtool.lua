
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

S=stream.STREAM("cmd:openssl x509 -text 2>/dev/null", "")
if S ~= nil then DecodePEMContents(cert, S) end

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


