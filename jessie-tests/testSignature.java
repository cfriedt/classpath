import gnu.javax.net.ssl.provider.Signature;
import gnu.javax.net.ssl.provider.SignatureAlgorithm;

import java.nio.ByteBuffer;
import java.util.Arrays;

class testSignature
{
  public static void main (String[] argv)
  {
    try
      {
        check ();
      }
    catch (Exception x)
      {
        System.out.println ("FAIL: caught exception " + x);
      }
  }

  static void check () throws Exception
  {
    ByteBuffer buffer = ByteBuffer.allocate (1024);
    Signature sig = new Signature (buffer, SignatureAlgorithm.RSA);
    byte[] sigbuf = new byte[256];
    for (int i = 0; i < sigbuf.length; i++)
      sigbuf[i] = (byte) i;

    sig.setSignature (sigbuf);

    sig = new Signature (buffer, SignatureAlgorithm.RSA);

    if (sig.length () == 258)
      System.out.println ("PASS: length");
    else
      System.out.println ("FAIL: length (" + sig.length () + ")");

    if (Arrays.equals (sigbuf, sig.signature ()))
      System.out.println ("PASS: signature");
    else
      System.out.println ("FAIL: signature");

    System.err.println (sig);
  }
}