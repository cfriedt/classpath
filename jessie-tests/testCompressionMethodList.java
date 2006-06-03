

import gnu.javax.net.ssl.provider.CompressionMethod;
import gnu.javax.net.ssl.provider.CompressionMethodList;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;

class testCompressionMethodList
{
  public static void main (String[] argv)
  {
    try
      {
        check ();
      }
    catch (Exception x)
      {
        System.out.println ("FAIL: uncaught exception " + x);
        x.printStackTrace ();
      }
  }

  static void check () throws Exception
  {
    ByteBuffer buffer = ByteBuffer.allocate (3);
    CompressionMethodList list = new CompressionMethodList (buffer);

    list.setSize (2);
    list.put (0, CompressionMethod.NULL);
    list.put (1, CompressionMethod.ZLIB);

    System.err.println (list);

    CompressionMethodList list2 = new CompressionMethodList (buffer);
    if (list2.equals (list))
      System.out.println ("PASS: equals()");
    else
      System.out.println ("FAIL: equals()");
  }
}
