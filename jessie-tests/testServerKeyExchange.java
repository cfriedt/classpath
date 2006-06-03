import gnu.javax.net.ssl.provider.CipherSuite;
import gnu.javax.net.ssl.provider.Handshake;
import gnu.javax.net.ssl.provider.ServerKeyExchange;
import gnu.javax.net.ssl.provider.ServerRSAParams;
import gnu.javax.net.ssl.provider.Signature;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

class testServerKeyExchange
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
        x.printStackTrace ();
      }
  }

  static void check () throws Exception
  {
    ByteBuffer buffer = ByteBuffer.allocate (1024);
    Handshake handshake = new Handshake (buffer, CipherSuite.SSL_RSA_WITH_NULL_MD5);

    handshake.setType (Handshake.Type.SERVER_KEY_EXCHANGE);
    handshake.setLength (1019);

    ServerKeyExchange kex = (ServerKeyExchange) handshake.body ();
    ServerRSAParams params = (ServerRSAParams) kex.params ();
    BigInteger modulus = new BigInteger ("FEEDFACEDEADBEEFCAFEBABE00000001", 16);
    BigInteger exponent = BigInteger.valueOf (2);
    params.setModulus (modulus);
    params.setExponent (exponent);

    Signature sig = kex.signature ();
    byte[] sigbuf = new byte[256];
    for (int i = 0; i < sigbuf.length; i++)
      sigbuf[i] = (byte) i;
    sig.setSignature (sigbuf);

    handshake.setLength (kex.length ());

    handshake = new Handshake (buffer, CipherSuite.SSL_RSA_WITH_NULL_MD5);
    kex = (ServerKeyExchange) handshake.body ();
    params = (ServerRSAParams) kex.params ();
    sig = kex.signature ();

    if (params.modulus ().equals (modulus))
      System.out.println ("PASS: modulus");
    else
      System.out.println ("FAIL: modulus " + modulus + " != " + params.modulus ());

    if (params.exponent ().equals (exponent))
      System.out.println ("PASS: exponent");
    else
      System.out.println ("FAIL: exponent " + exponent + " != " + params.exponent ());

    if (Arrays.equals (sigbuf, sig.signature ()))
      System.out.println ("PASS: signature");
    else
      System.out.println ("FAIL: signature");
  }
}