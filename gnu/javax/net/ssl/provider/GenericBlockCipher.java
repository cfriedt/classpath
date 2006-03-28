/* GenericBlockCipher.java -- 
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

class GenericBlockCipher extends CipheredStruct
{
  GenericBlockCipher (final ByteBuffer buffer, final int length,
                      final int macLength)
  {
    super (buffer, length, macLength);
  }

  GenericBlockCipher (final ByteBuffer buffer, final int macLength)
  {
    super (buffer, determineContentLength (buffer, macLength), macLength);
  }

  private static int determineContentLength (ByteBuffer buffer, int maclen)
  {
    int padlen = buffer.get (buffer.limit () - 1) & 0xFF;
    return buffer.limit () - maclen - padlen - 1;
  }

  public int length ()
  {
    return length + macLength + paddingLength () + 1;
  }

  int paddingLength ()
  {
    return buffer.get (buffer.limit () - 1) & 0xFF;
  }

  void setPaddingLength (final int paddingLength)
  {
    buffer.put (length + macLength + paddingLength, (byte) paddingLength);
  }

  byte[] padding ()
  {
    int len = paddingLength ();
    byte[] pad = new byte[len];
    buffer.position (length + macLength);
    buffer.get (pad);
    return pad;
  }

  /**
   * Sets the padding. Note, this assumes that the padding length has
   * already been set.
   */
  void setPadding (final byte[] pad, final int offset)
  {
    int len = paddingLength ();
    buffer.position (length + macLength);
    buffer.put (pad, offset, len);
  }

  void setPadding (final byte[] pad)
  {
    setPadding (pad, 0);
  }

  public String toString ()
  {
    return toString (null);
  }

  public String toString (final String prefix)
  {
    StringWriter str = new StringWriter ();
    PrintWriter out = new PrintWriter (str);

    if (prefix != null) out.print (prefix);
    out.println ("struct {");
    if (prefix != null) out.print (prefix);
    out.println ("  content =");
    out.println (Util.hexDump (content (),
                               prefix != null ? (prefix + "  ") : "  "));
    if (prefix != null) out.print (prefix);
    out.print ("  mac = ");
    out.println (Util.toHexString (mac (), ':'));
    if (prefix != null) out.print (prefix);
    out.print ("  padding = ");
    out.println (Util.toHexString (padding (), ':'));
    if (prefix != null) out.print (prefix);
    out.println ("} GenericBlockCipher;");

    return str.toString ();
  }
}