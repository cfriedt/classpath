/* Record.java -- A single SSL Record.
   Copyright (C) 2006  Free Software Foundation, Inc.

This file is a part of GNU Classpath.

GNU Classpath is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version.

GNU Classpath is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Classpath; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
USA

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version.  */


package gnu.javax.net.ssl.provider;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;

/**
 * A SSL/TLS record structure. An SSL record is defined to be:
 *
 * <pre>
struct
{
  {@link ContentType}     type;
  {@link ProtocolVersion} version;
  uint16          length;
  opaque          fragment[TLSPlaintext.length];
} TLSPlaintext;
</pre>
 */
class Record
{
  private final ByteBuffer buffer;

  Record (final ByteBuffer buffer)
  {
    this.buffer = buffer;
  }

  /**
   * Gets the content type field.
   *
   * @return The content type field.
   */
  ContentType getContentType ()
  {
    return ContentType.forInteger (buffer.get (0) & 0xFF);
  }

  /**
   * Get the fragment content, storing it into <code>sink</code>.
   *
   * @param sink The sink for the fragment bytes.
   * @return The number of bytes put into <code>sink</code>
   */
  int getFragment (final ByteBuffer sink)
  {
    int length = getLength ();
    sink.put (((ByteBuffer) buffer.limit (5 + length).position (5)).slice ());
    return length;
  }

  /**
   * Returns the fragment field as a ByteBuffer. The returned buffer
   * is shared with this object's underlying buffer, so it will share
   * its attributes. For example, if the underlying buffer is
   * read-only, the returned buffer will be read-only.
   *
   * @return The fragment buffer.
   */
  ByteBuffer getFragment ()
  {
    int length = getLength ();
    return ((ByteBuffer) buffer.limit (5 + length).position (5)).slice ();
  }

  /**
   * Gets the fragment length.
   *
   * @return The fragment length.
   */
  int getLength ()
  {
    return buffer.getShort (3) & 0xFFFF;
  }

  /**
   * Gets the protocol version field.
   *
   * @return The protocol version field.
   */
  ProtocolVersion getVersion ()
  {
    int major = buffer.get (1) & 0xFF;
    int minor = buffer.get (2) & 0xFF;
    return ProtocolVersion.getInstance (major, minor);
  }

  /**
   * Sets the content type field.
   *
   * @param type The content type.
   * @throws java.nio.ReadOnlyBufferException If the underlying buffer
   * is not writeable.
   * @throws NullPointerException If <i>type</i> is <code>null</code>.
   */
  void setContentType (final ContentType type)
  {
    buffer.put (0, (byte) type.getValue ());
  }

  /**
   * Sets the fragment length.
   *
   * @param length The fragment length.
   * @throws java.nio.ReadOnlyBufferException If the underlying buffer
   * is not writeable.
   * @throws IllegalArgumentException If the length is not between 0
   * and 16384, inclusive.
   */
  void setLength (final int length)
  {
    if (length < 0 || length > 16384)
      throw new IllegalArgumentException ("length " + length + " out of range; "
                                          + "must be between 0 and 16384");
    buffer.putShort (3, (short) length);
  }

  /**
   * Sets the protocol version field.
   *
   * @param version The protocol version.
   * @throws java.nio.ReadOnlyBufferException If the underlying buffer
   * is not writeable.
   * @throws NullPointerException If <i>version</i> is <code>null</code>.
   */
  void setVersion (final ProtocolVersion version)
  {
    buffer.put (1, (byte) version.getMajor ()).put (2, (byte) version.getMinor ());
  }

  public String toString ()
  {
    StringWriter str = new StringWriter ();
    PrintWriter out = new PrintWriter (str);
    out.println ("struct {");
    out.print ("  type:    ");
    out.print (getContentType ());
    out.println (";");
    out.print ("  version: ");
    out.print (getVersion ());
    out.println (";");
    out.println ("  fragment {");
    out.print (Util.hexDump (getFragment (), "    "));
    out.println ("  };");
    out.print ("} Record;");
    return str.toString ();
  }
}
