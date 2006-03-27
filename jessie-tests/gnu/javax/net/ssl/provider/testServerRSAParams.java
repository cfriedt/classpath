

package gnu.javax.net.ssl.provider;

import java.math.BigInteger;
import java.nio.ByteBuffer;

class testServerRSAParams
{
  public static void main (String[] argv) throws Throwable
  {
    BigInteger modulus = new BigInteger ("1234567890abcdef1234567890abcdef1234567890abcdef", 16);
    BigInteger exponent = BigInteger.valueOf (0xff);
    ByteBuffer buffer = ByteBuffer.allocate (1024);

    ServerRSAParams params = new ServerRSAParams (buffer);

    params.setModulus (modulus);
    params.setExponent (exponent);

    if (!params.getModulus ().equals (modulus))
      System.out.println ("FAIL: " + modulus + " != " + params.getModulus ());
    if (!params.getExponent ().equals (exponent))
      System.out.println ("FAIL: " + exponent + " != " + params.getExponent ());

    System.err.println (params);
  }
}
