/* ServerHello.java -- SSL ServerHello message.
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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;

import java.nio.ByteBuffer;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.SSLProtocolException;

/**
 * The server hello message.
 *
 * <pre>
struct
{
  ProtocolVersion server_version;
  Random random;
  SessionID session_id;
  CipherSuite cipher_suite;
  CompressionMethod compression_method;
} ServerHello;
</pre>
 *
 * <p>Server hello messages may contain extra data after the
 * <tt>compression_method</tt> field, which are interpreted as
 * extensions to the basic handshake.
 */
public class ServerHello implements Handshake.Body
{

  // Fields.
  // -------------------------------------------------------------------------

  private static final int RANDOM_OFFSET = 2;
  private static final int SESSID_OFFSET = 32 + RANDOM_OFFSET;
  private static final int SESSID_OFFSET2 = SESSID_OFFSET + 1;

  private final ByteBuffer buffer;

  /** The total length of the message, including the extensions. */
  private int totalLength;

  // Constructor.
  // -------------------------------------------------------------------------

  public ServerHello (final ByteBuffer buffer)
  {
    this.buffer = buffer;
  }

  public int length ()
  {
    return totalLength;
  }

  /**
   * Returns the server's protocol version. This will read two bytes
   * from the beginning of the underlying buffer, and return an
   * instance of the appropriate {@link ProtocolVersion}; if the
   * version read is a supported version, this method returns a static
   * constant instance.
   *
   * @return The server's protocol version.
   */
  public ProtocolVersion version()
  {
    return ProtocolVersion.getInstance (buffer.getShort (0));
  }

  /**
   * Returns the server's random value. This method returns a
   * lightwieght wrapper around the existing bytes; modifications to
   * the underlying buffer will modify the returned object, and
   * vice-versa.
   *
   * @return The server's random value.
   */
  public Random random()
  {
    ByteBuffer randomBuf =
      ((ByteBuffer) buffer.duplicate ().position (RANDOM_OFFSET)
       .limit (SESSID_OFFSET)).slice ();
    return new Random (randomBuf);
  }

  /**
   * Returns the session ID. This method returns a new byte array with
   * the session ID bytes.
   *
   * @return The session ID.
   */
  public byte[] sessionId()
  {
    int idlen = buffer.get (SESSID_OFFSET) & 0xFF;
    byte[] sessionId = new byte[idlen];
    buffer.position (SESSID_OFFSET2);
    buffer.get (sessionId);
    return sessionId;
  }

  /**
   * Returns the server's chosen cipher suite. The returned cipher
   * suite will be "resolved" to this structure's version.
   *
   * @return The server's chosen cipher suite.
   */
  public CipherSuite cipherSuite ()
  {
    int offset = SESSID_OFFSET + (buffer.get (SESSID_OFFSET) & 0xFF) + 1;
    return (CipherSuite.forValue (buffer.getShort (offset))
            .resolve (version ()));
  }

  /**
   * Returns the server's chosen compression method.
   *
   * @return The chosen compression method.
   */
  public CompressionMethod compressionMethod ()
  {
    int offset = SESSID_OFFSET + (buffer.get (SESSID_OFFSET) & 0xFF) + 3;
    return CompressionMethod.getInstance (buffer.get (offset) & 0xFF);
  }

  public ByteBuffer extensions ()
  {
    int offset = SESSID_OFFSET + (buffer.get (SESSID_OFFSET) & 0xFF) + 4;
    return ((ByteBuffer) buffer.duplicate ().position (offset)
            .limit (totalLength)).slice ();
  }

  public void setVersion (final ProtocolVersion version)
  {
    buffer.putShort (0, (short) version.rawValue ());
  }

  public void setSessionId (final byte[] sessionId)
  {
    setSessionId (sessionId, 0, sessionId.length);
  }

  public void setSessionId (final byte[] sessionId, final int offset,
                            final int length)
  {
    int len = Math.min (length, 32);
    buffer.put (SESSID_OFFSET, (byte) len);
    buffer.position (SESSID_OFFSET2);
    buffer.put (sessionId, offset, len);
  }

  public void setCipherSuite (final CipherSuite suite)
  {
    int offset = SESSID_OFFSET + (buffer.get (SESSID_OFFSET) & 0xFF) + 1;
    buffer.position (offset);
    buffer.put (suite.id ());
  }

  public void setCompressionMethod (final CompressionMethod comp)
  {
    int offset = SESSID_OFFSET + (buffer.get (SESSID_OFFSET) & 0xFF) + 3;
    buffer.put (offset, (byte) comp.getValue ());
  }

  public void setExtensionsLength (final int length)
  {
    totalLength = (SESSID_OFFSET + (buffer.get (SESSID_OFFSET) & 0xFF)
                   + 4 + length);
  }

  public String toString ()
  {
    return toString (null);
  }

  public String toString (final String prefix)
  {
    StringWriter str = new StringWriter();
    PrintWriter out = new PrintWriter(str);
    if (prefix != null)
      out.print (prefix);
    out.println ("struct {");
    String subprefix = "  ";
    if (prefix != null)
      subprefix += prefix;
    out.print (subprefix);
    out.print ("version: ");
    out.print (version ());
    out.println (";");
    out.print (subprefix);
    out.println ("random:");
    out.println (random ().toString (subprefix));
    out.print (subprefix);
    out.print ("sessionId:         ");
    out.print (Util.toHexString(sessionId (), ':'));
    out.println (";");
    out.print (subprefix);
    out.print ("cipherSuite:       ");
    out.print (cipherSuite ());
    out.println (";");
    out.print (subprefix);
    out.print ("compressionMethod: ");
    out.print (compressionMethod ());
    out.println (";");
    ByteBuffer extbuf = extensions ();
    if (extbuf.limit () > 0)
      {
        out.print (subprefix);
        out.println ("extensions:");
        out.print (Util.hexDump (extbuf, subprefix));
      }
    if (prefix != null)
      out.print (prefix);
    out.print ("} ServerHello;");
    return str.toString();
  }
}
