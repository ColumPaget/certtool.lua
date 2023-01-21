require("terminal")
require("strutil")
require("filesys")
require("process")
require("stream")
require("time")



Version="1.1"
KeyStore={}
ExitStatus=0
g_Debug=false

CARootCerts={}
CARootURLs="https://letsencrypt.org/certs/isrgrootx1.pem.txt,https://dl.cacerts.digicert.com/BaltimoreCyberTrustRoot.crt.pem,https://dl.cacerts.digicert.com/CybertrustGlobalRoot.crt.pem,DigiCert Assured ID,https://dl.cacerts.digicert.com/DigiCertAssuredIDRootCA.crt.pem,DigiCert Assured ID G2,https://dl.cacerts.digicert.com/DigiCertAssuredIDRootG2.crt.pem,DigiCert Assured ID G3,https://dl.cacerts.digicert.com/DigiCertAssuredIDRootG3.crt.pem,DigiCert Federated ID,https://dl.cacerts.digicert.com/DigiCertFederatedIDRootCA.crt.pem,DigiCert Global,https://dl.cacerts.digicert.com/DigiCertGlobalRootCA.crt.pem,DigiCert Global G2,https://dl.cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem,DigiCert Global G3,https://dl.cacerts.digicert.com/DigiCertGlobalRootG3.crt.pem,DigiCert High Assurance EV,https://dl.cacerts.digicert.com/DigiCertHighAssuranceEVRootCA.crt.pem,DigiCert Trusted G4,https://dl.cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem,GTE Cybetrust Global,https://dl.cacerts.digicert.com/GTECyberTrustGlobalRoot.crt.pem,Verizon Global,https://dl.cacerts.digicert.com/VerizonGlobalRootCA.crt.pem,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA.pem,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA_G2_ECC.pem,GeoTrust Primary G3,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA_G4_DSA.pem,GeoTrust Primary G4,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Primary_CA_G4_DSA.pem,GeoTrust Universal,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA.pem,GeoTrust Universal,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA.pem,GeoTrust Universal 2,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA2.pem,GeoTrust Global,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Universal_CA2.pem,GeoTrust Global 2,https://www.geotrust.com/resources/root_certificates/certificates/GeoTrust_Global_CA2.pem"

