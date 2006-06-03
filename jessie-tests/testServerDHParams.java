

import gnu.javax.net.ssl.provider.ServerDHParams;

import java.math.BigInteger;
import java.nio.ByteBuffer;

class testServerDHParams
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
    BigInteger p = new BigInteger ("1234567890abcdef1234567890abcdef1234567890abcdef", 16);
    BigInteger g = BigInteger.valueOf (2);
    BigInteger y = new BigInteger ("fedcba0987654321fedcba0987654321fedcba0987654321", 16);
    ByteBuffer buffer = ByteBuffer.allocate (1024);

    ServerDHParams params = new ServerDHParams (buffer);

    params.setP (p);
    params.setG (g);
    params.setY (y);

    if (params.p ().equals (p))
      System.out.println ("PASS: p");
    else
      System.out.println ("FAIL: " + p + " != " + params.p ());

    if (params.g ().equals (g))
      System.out.println ("PASS: g");
    else
      System.out.println ("FAIL: " + g + " != " + params.g ());

    if (params.y ().equals (y))
      System.out.println ("PASS: y");
    else
      System.out.println ("FAIL: " + y + " != " + params.y ());

    System.err.println (params);
  }
}
