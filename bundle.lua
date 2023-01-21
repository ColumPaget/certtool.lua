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

