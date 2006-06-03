

import gnu.javax.net.ssl.provider.ContentType;
import gnu.javax.net.ssl.provider.ProtocolVersion;
import gnu.javax.net.ssl.provider.Record;

import java.nio.ByteBuffer;
import java.util.Arrays;

class testRecord
{
  public static void main (final String[] argv)
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
    ByteBuffer buf = ByteBuffer.allocate (42 + 5);
    Record record = new Record (buf);
    byte[] fragment = new byte[42];
    new java.util.Random (31337).nextBytes (fragment);

    record.setVersion (ProtocolVersion.TLS_1);
    System.out.println ("PASS: setVersion");
    record.setContentType (ContentType.APPLICATION_DATA);
    System.out.println ("PASS: setContentType");
    record.setLength (42);
    System.out.println ("PASS: setLength");

    record.fragment ().put (fragment);
    System.out.println ("PASS: fragment ().put ()");

    if (ProtocolVersion.TLS_1.equals (record.version ()))
      System.out.println ("PASS: version()");
    else
      System.out.println ("FAIL: version()");

    if (ContentType.APPLICATION_DATA.equals (record.contentType ()))
      System.out.println ("PASS: contentType()");
    else
      System.out.println ("FAIL: contentType()");

    if (record.length () == 42)
      System.out.println ("PASS: length()");
    else
      System.out.println ("FAIL: length()");

    byte[] fragment2 = new byte[42];
    record.fragment ().get (fragment2);
    if (Arrays.equals (fragment, fragment2))
      System.out.println ("PASS: fragment ().get ()");
    else
      System.out.println ("FAIL: fragment ().get ()");

    System.err.println (record);
  }
}
