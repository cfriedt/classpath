/* AbstractHandshake.java -- abstract handshake handler.
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

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

/**
 * The base interface for handshake implementations. Concrete
 * subclasses of this class (one for the server, one for the client)
 * handle the HANDSHAKE content-type in communications.
 */
public abstract class AbstractHandshake
{

  /**
   * The currently-read handshake messages. There may be zero, or
   * multiple, handshake messages in this buffer.
   */
  protected ByteBuffer handshakeBuffer;

  /**
   * The offset into `handshakeBuffer' where the first unread
   * handshake message resides.
   */
  protected int handshakeOffset;

  /**
   * Handles the next input message in the handshake. This is called
   * in response to a call to {@link javax.net.ssl.SSLEngine#unwrap}
   * for a message with content-type HANDSHAKE.
   *
   * @param record The input record. The callee should not assume that
   * the record's buffer is writable, and should not try to use it for
   * output or temporary storage.
   * @return An {@link SSLEngineResult} describing the result.
   */
  public abstract SSLEngineResult handleInput (Record record) throws SSLException;

  /**
   * Produce more handshake output. This is called in response to a
   * call to {@link javax.net.ssl.SSLEngine#wrap}, when the handshake
   * is still in progress.
   *
   * @param record The output record; the callee should put its output
   * handshake message (or a part of it) in the argument's
   * <code>fragment</code>, and should set the record length
   * appropriately.
   * @return An {@link SSLEngineResult} describing the result.
   */
  public abstract SSLEngineResult handleOutput (Record record) throws SSLException;

  /**
   * Attempt to read the next handshake message from the given
   * record. If only a partial handshake message is available, then
   * this method saves the incoming bytes and returns false. If a
   * complete handshake is read, or if there was one buffered in the
   * handshake buffer, this method returns true, and `handshakeBuffer'
   * can be used to read the handshake.
   *
   * @param record The input record.
   * @return True if a complete handshake is present in the buffer;
   * false if only a partial one.
   */
  protected boolean pollHandshake (final Record record)
  {
    // Allocate space for the new fragment.
    if (handshakeBuffer == null || handshakeBuffer.remaining () < record.length ())
      {
        // We need space for anything still unread in the handshake
        // buffer...
        int len = ((handshakeBuffer == null) ? 0
                   : handshakeBuffer.position () - handshakeOffset);

        // Plus room for the incoming record.
        len += record.length ();
        reallocateBuffer (len);
      }

    // Put the fragment into the buffer.
    handshakeBuffer.put (record.fragment ());

    return hasMessage ();
  }

  /**
   * Tell if the handshake buffer currently has a full handshake
   * message.
   */
  protected boolean hasMessage ()
  {
    if (handshakeBuffer == null)
      return false;
    ByteBuffer tmp = handshakeBuffer.duplicate ();
    tmp.flip ();
    tmp.position (handshakeOffset);
    Handshake handshake = new Handshake (tmp);
    return (handshake.length () >= tmp.remaining ());
  }

  /**
   * Reallocate the handshake buffer so it can hold `totalLen'
   * bytes. The smallest buffer allocated is 1024 bytes, and the size
   * doubles from there until the buffer is sufficiently large.
   */
  private void reallocateBuffer (final int totalLen)
  {
    int len = handshakeBuffer == null ? 0 : handshakeBuffer.capacity ();
    if (len >= totalLen)
      return; // Big enough; no need to reallocate.

    // Start at 1K (probably the system's page size). Double the size
    // from there.
    len = 1024;
    while (len < totalLen)
      len = len << 1;
    ByteBuffer newBuf = ByteBuffer.allocate (len);

    // Copy the unread bytes from the old buffer.
    if (handshakeBuffer != null)
      {
        handshakeBuffer.flip ();
        handshakeBuffer.position (handshakeOffset);
        newBuf.put (handshakeBuffer);
      }
    handshakeBuffer = newBuf;

    // We just put only unread handshake messages in the new buffer;
    // the offset of the next one is now zero.
    handshakeOffset = 0;
  }
}