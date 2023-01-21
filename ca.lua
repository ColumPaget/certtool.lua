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
