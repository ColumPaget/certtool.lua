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
