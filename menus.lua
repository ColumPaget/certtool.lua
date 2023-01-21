
function CertAuthorityMenu()
local Menu, choice

Out:clear()
Menu=terminal.TERMMENU(Out, 1, 1, Out:width() - 2, Out:length() - 2)
Menu:add("Create New CA", "new")

dirs=filesys.GLOB(WorkingDir.."*")
item=dirs:next()
while item ~= nil
do
	if filesys.exists(item.."/serial") then Menu:add(filesys.basename(item), item) end
item=dirs:next()
end


choice=Menu:run()

if strutil.strlen(choice) > 0
then
	if choice=="new" then CreateNewCA()
	else CreateCertificate(choice)
	end
end

end



