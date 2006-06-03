

import gnu.javax.net.ssl.provider.ServerRSAParams;

import java.math.BigInteger;
import java.nio.ByteBuffer;

class testServerRSAParams
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
    BigInteger modulus = new BigInteger ("1234567890abcdef1234567890abcdef1234567890abcdef", 16);
    BigInteger exponent = BigInteger.valueOf (0xff);
    ByteBuffer buffer = ByteBuffer.allocate (1024);

    ServerRSAParams params = new ServerRSAParams (buffer);

    params.setModulus (modulus);
    params.setExponent (exponent);

    params = new ServerRSAParams (buffer);

    if (params.modulus ().equals (modulus))
      System.out.println ("PASS: modulus");
    else
      System.out.println ("FAIL: " + modulus + " != " + params.modulus ());

    if (params.exponent ().equals (exponent))
      System.out.println ("PASS: exponent");
    else
      System.out.println ("FAIL: " + exponent + " != " + params.exponent ());

    System.err.println (params);
  }
}
