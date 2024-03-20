
function ParseCommandLine()
local Cmd={}
local i, item, toks

Cmd.path=""
Cmd.outpath="-"
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


