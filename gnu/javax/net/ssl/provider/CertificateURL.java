package gnu.javax.net.ssl.provider;

import gnu.javax.net.ssl.provider.Extension.Value;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.NoSuchElementException;

/**
 * The CertificateURL extension value.
 * 
 * <pre>
enum {
  individual_certs(0), pkipath(1), (255)
} CertChainType;

enum {
  false(0), true(1)
} Boolean;

struct {
  CertChainType type;
  URLAndOptionalHash url_and_hash_list&lt;1..2^16-1&gt;;
} CertificateURL;

struct {
  opaque url&lt;1..2^16-1&gt;;
  Boolean hash_present;
  select (hash_present) {
    case false: struct {};
    case true: SHA1Hash;
  } hash;
} URLAndOptionalHash;

opaque SHA1Hash[20];</pre>
 *
 * @author csm
 *
 */
public class CertificateURL extends Value implements Iterable<CertificateURL.URLAndOptionalHash>
{
  private final ByteBuffer buffer;
  
  public CertificateURL(final ByteBuffer buffer)
  {
    this.buffer = buffer;
  }
  
  public int length()
  {
    return 3 + (buffer.getShort(1) & 0xFFFF);
  }

  public CertChainType type()
  {
    switch (buffer.get(0))
      {
        case 0: return CertChainType.INDIVIDUAL_CERTS;
        case 1: return CertChainType.PKIPATH;
      }
    throw new IllegalArgumentException("unknown certificate URL type");
  }
  
  public int size()
  {
    int len = buffer.getShort(1) & 0xFFFF;
    int n = 0;
    for (int i = 3; i < len; )
      {
        URLAndOptionalHash u
          = new URLAndOptionalHash((ByteBuffer) buffer.duplicate().position(i));
        int l = u.length();
        i += l;
        n++;
      }
    return n;
  }
  
  public URLAndOptionalHash get(int index)
  {
    int len = buffer.getShort(1) & 0xFFFF;
    int n = 0;
    int l = 0;
    int i;
    for (i = 3; i < len && n < index; )
      {
        URLAndOptionalHash u
          = new URLAndOptionalHash((ByteBuffer) buffer.duplicate().position(i));
        l = u.length();
        i += l;
        n++;
      }
    if (n < index)
      throw new IndexOutOfBoundsException();
    return new URLAndOptionalHash(((ByteBuffer) buffer.duplicate().position(i).limit(i+l)).slice());
  }
  
  public void set(int index, URLAndOptionalHash url)
  {
    int len = buffer.getShort(1) & 0xFFFF;
    int n = 0;
    int i;
    for (i = 3; i < len && n < index-1; )
      {
        URLAndOptionalHash u
          = new URLAndOptionalHash((ByteBuffer) buffer.duplicate().position(i));
        int l = u.length();
        i += l;
        n++;
      }
    if (n < index - 1)
      throw new IndexOutOfBoundsException();
    int l = url.urlLength();
    buffer.putShort(i, (short) l);
    ((ByteBuffer) buffer.duplicate().position(i+2)).put(url.urlBuffer());
    buffer.put(i+l+2, (byte) (url.hashPresent() ? 1 : 0));
    if (url.hashPresent())
      ((ByteBuffer) buffer.duplicate().position(i+l+3)).put (url.sha1Hash());
  }
  
  public void setLength(final int length)
  {
    if (length < 0 || length > 65535)
      throw new IllegalArgumentException("length must be between 0 and 65535");
    buffer.putShort(1, (short) length);
  }
  
  public String toString()
  {
    return toString(null);
  }
  
  public String toString(String prefix)
  {
    StringWriter str = new StringWriter();
    PrintWriter out = new PrintWriter(str);
    if (prefix != null) out.print(prefix);
    out.println ("struct {");
    if (prefix != null) out.print(prefix);
    out.print("  type = ");
    out.print(type());
    out.println(";");
    if (prefix != null) out.print(prefix);
    out.println("  url_and_hash_list = {");
    String subprefix = "  ";
    if (prefix != null) subprefix = prefix + subprefix;
    for (URLAndOptionalHash url : this)
      {
        out.println(url.toString(subprefix));
      }
    if (prefix != null) out.print(prefix);
    out.println("  };");
    if (prefix != null) out.print(prefix);
    out.print("} CertificateURL;");
    return str.toString();
  }

  public java.util.Iterator<URLAndOptionalHash> iterator()
  {
    return new Iterator();
  }
  
  public class Iterator implements java.util.Iterator<URLAndOptionalHash>
  {
    private int index;
    
    public Iterator()
    {
      index = 0;
    }
    
    public URLAndOptionalHash next() throws NoSuchElementException
    {
      try
        {
          return get(index++);
        }
      catch (IndexOutOfBoundsException ioobe)
        {
          throw new NoSuchElementException();
        }
    }
    
    public boolean hasNext()
    {
      return index < size();
    }
    
    public void remove()
    {
      throw new UnsupportedOperationException();
    }
  }
  
  public static enum CertChainType
  {
    INDIVIDUAL_CERTS (0), PKIPATH (1);
    
    private final int value;
    
    private CertChainType (final int value)
    {
      this.value = value;
    }
    
    public int getValue()
    {
      return value;
    }
  }
  
  public static class URLAndOptionalHash implements Constructed
  {
    private final ByteBuffer buffer;
    
    public URLAndOptionalHash (final ByteBuffer buffer)
    {
      this.buffer = buffer;
    }
    
    public int length()
    {
      return ((buffer.getShort(0) & 0xFFFF)
              + (hashPresent() ? 23 : 3));
    }
    
    public String url()
    {
      Charset cs = Charset.forName("ASCII");
      return cs.decode(urlBuffer()).toString();
    }
    
    public int urlLength()
    {
      return buffer.getShort(0) & 0xFFFF;
    }
    
    public ByteBuffer urlBuffer()
    {
      int len = urlLength();
      return ((ByteBuffer) buffer.duplicate().position(2).limit(2+len)).slice();
    }
    
    public boolean hashPresent()
    {
      int i = (buffer.getShort(0) & 0xFFFF) + 2;
      byte b = buffer.get(i);
      if (b == 0)
        return false;
      if (b == 1)
        return true;
      throw new IllegalArgumentException("expecting 0 or 1: " + (b & 0xFF));
    }
    
    public byte[] sha1Hash()
    {
      int i = (buffer.getShort(0) & 0xFFFF) + 2;
      byte b = buffer.get(i);
      if (b == 0)
        return null;
      byte[] buf = new byte[20];
      ((ByteBuffer) buffer.duplicate().position(i+1)).get(buf);
      return buf;
    }
    
    public String toString()
    {
      return toString(null);
    }
    
    public String toString(final String prefix)
    {
      StringWriter str = new StringWriter();
      PrintWriter out = new PrintWriter(str);
      if (prefix != null) out.print(prefix);
      out.println("struct {");
      if (prefix != null) out.print(prefix);
      out.print("  url = ");
      out.print(url());
      out.println(";");
      boolean has_hash = hashPresent();
      if (prefix != null) out.print(prefix);
      out.print("  hash_present = ");
      out.print(has_hash);
      out.println(";");
      if (has_hash)
        {
          if (prefix != null) out.print(prefix);
          out.print("  sha1Hash = ");
          out.print(Util.toHexString(sha1Hash(), ':'));
          out.println(";");
        }
      if (prefix != null) out.print(prefix);
      out.print("} URLAndOptionalHash;");
      return str.toString();
    }
  }
}
