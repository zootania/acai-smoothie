import os
import sys
from collections import defaultdict
import lief


def signature(pe, type_of_binary):
        """
            Display PE signature if any
        """
        feature_set = defaultdict(list)
        sep = (":") if sys.version_info.minor > 7 else ()
        if (type_of_binary == 'EXEfile' or type_of_binary == 'DLLfile') and pe.has_signatures:
            
                feature_set['Signature'] = {}
                 # Get authenticode
                
                feature_set['Signature']['MD5 authentihash'] = str(pe.authentihash_md5.hex(*sep))
                feature_set['Signature']['SHA1 authentihash'] = str(pe.authentihash(lief.PE.ALGORITHMS.SHA_1).hex(*sep))
                
                #print(pe.authentihash_md5.hex(*sep)) # 1c:a0:91:53:dc:9a:3a:5f:34:1d:7f:9b:b9:56:69:4d
                #print(pe.authentihash(lief.PE.ALGORITHMS.SHA_1).hex(*sep)) # 1e:ad:dc:29:1e:db:41:a2:69:c2:ba:ae:4b:fb:9d:31:e7:bb:ab:59

                # Check signature according to PKCS #7 and Microsoft documentation
                #feature_set['Signature']['Verification flag']= str(pe.verify_signature()) # Return VERIFICATION_FLAGS.OK

                bin_ca = None
                # Look for the root CA in the PE file
                for crt in pe.signatures[0].certificates:
                    if crt.issuer == "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA":
                        bin_ca = crt

                # Verify CA chain
                bundle_path = os.getenv("LIEF_CA_BUNDLE", None) # Path to CA bundle (one can use those from signify:# signify/certs/authenticode-bundle.pem)
                #print(bundle_path)
                
                if bundle_path is not None:
                    # Parse cert bundle and return a list of lief.PE.x509 objects
                    bundle = lief.PE.x509.parse(bundle_path)
                    #feature_set['Signature']['Bundle path'] = bin_ca.is_trusted_by(bundle) # VERIFICATION_FLAGS.OK

                #print("here second stop")
                # Get the certificate used by the signer
                
                cert_signer = pe.signatures[0].signers[0].cert
                a = str(cert_signer)
                cert = [{i.split(" : ")[0].strip():i.split(" : ")[1].strip()}  for i in a.split("\n") if len(i.split(" : ")) > 1]
                feature_set['Signature']['Signer details'] = cert
                #print(bin_ca)


        return feature_set

                    
