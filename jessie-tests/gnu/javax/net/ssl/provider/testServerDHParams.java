

package gnu.javax.net.ssl.provider;

import java.math.BigInteger;
import java.nio.ByteBuffer;

class testServerDHParams
{
  public static void main (String[] argv) throws Throwable
  {
    BigInteger p = new BigInteger ("1234567890abcdef1234567890abcdef1234567890abcdef", 16);
    BigInteger g = BigInteger.valueOf (2);
    BigInteger y = new BigInteger ("fedcba0987654321fedcba0987654321fedcba0987654321", 16);
    ByteBuffer buffer = ByteBuffer.allocate (1024);

    ServerDHParams params = new ServerDHParams (buffer);

    params.setP (p);
    params.setG (g);
    params.setY (y);

    if (!params.getP ().equals (p))
      System.out.println ("FAIL: " + p + " != " + params.getP ());
    if (!params.getG ().equals (g))
      System.out.println ("FAIL: " + g + " != " + params.getG ());
    if (!params.getY ().equals (y))
      System.out.println ("FAIL: " + y + " != " + params.getY ());

    System.err.println (params);
  }
}
