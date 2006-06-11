package gnu.javax.net.ssl.provider;

import gnu.javax.net.ssl.provider.Extension.Value;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;

public class UnresolvedExtensionValue extends Value
{
  private final ByteBuffer buffer;
  
  public UnresolvedExtensionValue (final ByteBuffer buffer)
  {
    this.buffer = buffer;
  }
  
  public int length()
  {
    return buffer.limit();
  }
  
  public ByteBuffer value()
  {
    return buffer.slice();
  }
  
  public String toString()
  {
    return toString(null);
  }
  
  public String toString(final String prefix)
  {
    String s = Util.hexDump(buffer);
    if (prefix != null)
      s = prefix + s;
    return s;
  }
}
