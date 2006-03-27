

package gnu.javax.net.ssl.provider;

import java.nio.ByteBuffer;
import java.util.Arrays;

class testRecord
{
  public static void main (final String[] argv)
  {
    ByteBuffer buf = ByteBuffer.allocate (42 + 5);
    Record record = new Record (buf);
    byte[] fragment = new byte[42];
    new java.util.Random (31337).nextBytes (fragment);
    try
      {
        record.setVersion (ProtocolVersion.TLS_1);
        System.out.println ("PASS: setVersion");
        record.setContentType (ContentType.APPLICATION_DATA);
        System.out.println ("PASS: setContentType");
        record.setLength (42);
        System.out.println ("PASS: setLength");
      }
    catch (Throwable t)
      {
        System.out.println ("FAIL: " + t);
        System.exit (1);
      }

    try
      {
        record.getFragment ().put (fragment);
        System.out.println ("PASS: getFragment ().put ()");
      }
    catch (Throwable t)
      {
        System.out.println ("FAIL: " + t);
        System.exit (1);
      }

    if (ProtocolVersion.TLS_1.equals (record.getVersion ()))
      System.out.println ("PASS: getVersion()");
    else
      System.out.println ("FAIL: getVersion()");

    if (ContentType.APPLICATION_DATA.equals (record.getContentType ()))
      System.out.println ("PASS: getContentType()");
    else
      System.out.println ("FAIL: getContentType()");

    if (record.getLength () == 42)
      System.out.println ("PASS: getLength()");
    else
      System.out.println ("FAIL: getLength()");

    byte[] fragment2 = new byte[42];
    record.getFragment ().get (fragment2);
    if (Arrays.equals (fragment, fragment2))
      System.out.println ("PASS: getFragment ().get ()");
    else
      System.out.println ("FAIL: getFragment ().get ()");

    System.err.println (record);
  }
}
