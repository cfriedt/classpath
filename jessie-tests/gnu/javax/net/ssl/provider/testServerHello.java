

package gnu.javax.net.ssl.provider;

import java.nio.ByteBuffer;

class testServerHello
{
  public static void main (String[] argv) throws Exception
  {
    final int alloc_len = 4096;
    ByteBuffer buffer = ByteBuffer.allocate (alloc_len);
    Handshake handshake = new Handshake (buffer);

    handshake.setType (Handshake.Type.SERVER_HELLO);
    handshake.setLength (alloc_len - 4);

    ServerHello hello = (ServerHello) handshake.getBody ();

    hello.setProtocolVersion (ProtocolVersion.TLS_1);
    Random random = hello.getRandom ();
    random.setGMTUnixTime (123456);
    byte[] nonce = new byte[28];
    for (int i = 0; i < nonce.length; i++)
      nonce[i] = (byte) i;
    random.setRandomBytes (nonce);
    byte[] sessionId = new byte[32];
    for (int i = 0; i < sessionId.length; i++)
      sessionId[i] = (byte) i;
    hello.setSessionId (sessionId);
    hello.setCipherSuite (CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
    hello.setCompressionMethod (CompressionMethod.ZLIB);
    hello.setExtensionsLength (0);

    handshake.setLength (hello.getLength ());
    System.err.println (handshake);
  }
}
