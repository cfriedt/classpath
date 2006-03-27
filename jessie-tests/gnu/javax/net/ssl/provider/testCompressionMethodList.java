

package gnu.javax.net.ssl.provider;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;

class testCompressionMethodList
{
  public static void main (String[] argv) throws Exception
  {
    ByteBuffer buffer = ByteBuffer.allocate (3);
    CompressionMethodList list = new CompressionMethodList (buffer);

    list.setSize (2);
    list.put (0, CompressionMethod.NULL);
    list.put (1, CompressionMethod.ZLIB);
    System.err.println (list);
  }
}
