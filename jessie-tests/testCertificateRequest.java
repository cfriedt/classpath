import gnu.javax.net.ssl.provider.CertificateRequest;
import gnu.javax.net.ssl.provider.ClientCertificateTypeList;
import gnu.javax.net.ssl.provider.X500PrincipalList;

import java.nio.ByteBuffer;
import javax.security.auth.x500.X500Principal;

class testCertificateRequest
{
  public static void main (String[] argv) throws Throwable
  {
    try
      {
        check ();
      }
    catch (Exception x)
      {
        System.out.println ("FAIL: caught exception " + x);
        x.printStackTrace ();
      }
  }

  static void check () throws Exception
  {
    ByteBuffer buffer = ByteBuffer.allocate (4096);
    System.err.println ("create X500Principal...");
    X500Principal name = new X500Principal ("C=US,ST=MA,L=Boston,O=FSF,OU=Certificate Authority,CN=savannah.gnu.org");
    System.err.println (name);
    CertificateRequest req = new CertificateRequest (buffer);

    System.err.println ("getting types...");
    ClientCertificateTypeList types = req.types ();
    types.setSize (4);
    System.err.println ("adding types...");
    types.put (0, CertificateRequest.ClientCertificateType.DSS_FIXED_DH);
    types.put (1, CertificateRequest.ClientCertificateType.RSA_FIXED_DH);
    types.put (2, CertificateRequest.ClientCertificateType.DSS_SIGN);
    types.put (3, CertificateRequest.ClientCertificateType.RSA_SIGN);

    System.err.println ("getting names...");
    X500PrincipalList names = req.authorities ();
    byte[] bytes = name.getEncoded ();
    names.setSize (1, bytes.length);
    System.err.println ("putting name...");
    names.put (0, bytes);

    System.err.println (req);

    CertificateRequest req2 = new CertificateRequest (buffer);
    ClientCertificateTypeList types2 = req2.types ();
    X500PrincipalList names2 = req2.authorities ();
    if (types2.equals (types))
      System.out.println ("PASS: equals(types)");
    else
      System.out.println ("FAIL: equals(types)");
    if (names2.equals (names))
      System.out.println ("PASS: equals(names)");
    else
      System.out.println ("FAIL: equals(names)");
  }
}
