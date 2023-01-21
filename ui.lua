
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

