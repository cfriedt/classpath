

package gnu.javax.net.ssl.provider;

import java.nio.ByteBuffer;
import javax.security.auth.x500.X500Principal;

class testCertificateRequest
{
  public static void main (String[] argv) throws Throwable
  {
    ByteBuffer buffer = ByteBuffer.allocate (4096);
    System.err.println ("create X500Principal...");
    X500Principal name = new X500Principal ("C=US,ST=MA,L=Boston,O=FSF,OU=Certificate Authority,CN=savannah.gnu.org");
    System.err.println (name);
    CertificateRequest req = new CertificateRequest (buffer);

    System.err.println ("getting types...");
    ClientCertificateTypeList types = req.getTypes ();
    types.setSize (4);
    System.err.println ("adding types...");
    types.put (0, CertificateRequest.ClientCertificateType.DSS_FIXED_DH);
    types.put (1, CertificateRequest.ClientCertificateType.RSA_FIXED_DH);
    types.put (2, CertificateRequest.ClientCertificateType.DSS_SIGN);
    types.put (3, CertificateRequest.ClientCertificateType.RSA_SIGN);

    System.err.println ("getting names...");
    X500PrincipalList names = req.getAuthorities ();
    byte[] bytes = name.getEncoded ();
    names.setSize (1, bytes.length);
    System.err.println ("putting name...");
    names.put (0, bytes);

    System.err.println (req);
  }
}
