

package gnu.javax.net.ssl.provider;

import java.nio.ByteBuffer;

class testHelloRequest
{
  public static void main (String[] argv) throws Throwable
  {
    ByteBuffer buffer = ByteBuffer.allocate (4);
    Handshake handshake = new Handshake (buffer);
    handshake.setType (Handshake.Type.HELLO_REQUEST);
    handshake.setLength (0);
    Handshake.Body body = handshake.getBody ();

    if (!(body instanceof HelloRequest))
      System.out.println ("FAIL: " + body.getClass ());

    System.err.println (handshake);
  }
}
