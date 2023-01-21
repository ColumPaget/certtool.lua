
function CertDetailsCreate()
local details={}

details.pem=""
details.subject=""
details.name=""
details.alt_names=""
details.org=""
details.country=""
details.location=""
details.email=""
details.issuer=""
details.issuer_org=""
details.issuer_country=""
details.start_date=""
details.end_date=""
details.start_time=""
details.end_time=""
details.lifetime=""


return details
end




function CertDetailsFromCmd(cmd)
local details

details=CertDetailsCreate()
details.name=cmd.path
details.cert_authority=cmd.cert_authority
details.org=cmd.org
details.location=cmd.location
details.email=cmd.email
details.lifetime=cmd.lifetime

return details
end


