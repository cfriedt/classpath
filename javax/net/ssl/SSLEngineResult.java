/* SSLEngineResult.java -- 
   Copyright (C) 2006 Free Software Foundation, Inc.

This file is part of GNU Classpath.

GNU Classpath is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

GNU Classpath is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Classpath; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
02111-1307 USA.

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
exception statement from your version. */


package javax.net.ssl;

import gnu.java.lang.PseudoEnum;

/**
 * A result from an {@link SSLEngine} <code>wrap</code> or
 * <code>unwrap</code> operation. This class conveys a possibly
 * intermediate result, and may ask for more input data or request
 * that output data be sent over a connection.
 */
public class SSLEngineResult
{
  private final HandshakeStatus handshakeStatus;
  private final Status status;
  private final int bytesConsumed;
  private final int bytesProduced;

  /**
   * Creates a new SSL engine result.
   *
   * @param status The status of the SSL connection.
   * @param handshakeStatus The status of the SSL handshake.
   * @param bytesConsumed The number of bytes consumed by the previous
   * operation.
   * @param bytesProduced The number of bytes produced by the previous
   * operation.
   * @throws IllegalArgumentException If either enum value is
   * <code>null</code>, or if either integer is negative.
   */
  public SSLEngineResult (Status status, HandshakeStatus handshakeStatus,
			  int bytesConsumed, int bytesProduced)
  {
    if (status == null)
      throw new IllegalArgumentException ("'status' may not be null");
    if (handshakeStatus == null)
      throw new IllegalArgumentException ("'handshakeStatus' may not be null");
    if (bytesConsumed < 0)
      throw new IllegalArgumentException ("'bytesConumed' must be nonnegative");
    if (bytesProduced < 0)
      throw new IllegalArgumentException ("'bytesProduced' must be nonnegative");
    this.status = status;
    this.handshakeStatus = handshakeStatus;
    this.bytesConsumed = bytesConsumed;
    this.bytesProduced = bytesProduced;
  }



  /**
   * An enumeration of possible general states.
   */
  public static class Status extends PseudoEnum // FIXME ENUM 1.5
  {

    /**
     * There were not enough input bytes available to complete the
     * operation.
     */
    public static final Status BUFFER_UNDERFLOW = new Status (0, "BUFFER_UNDERFLOW");

    /**
     * There was not enough space for the output message.
     */
    public static final Status BUFFER_OVERFLOW = new Status (1, "BUFFER_OVERFLOW");

    /**
     * Okay. No error.
     */
    public static final Status OK = new Status (2, "OK");

    /**
     * The connection is closed.
     */
    public static final Status CLOSED = new Status (3, "CLOSED");

    private Status (final int ordinal, final String name)
    {
      super (ordinal, name, Status.class);
    }

    public static Status[] values ()
    {
      return new Status[] { BUFFER_UNDERFLOW, BUFFER_OVERFLOW, OK, CLOSED };
    }

    public static Status valueOf (final String name)
    {
      if (name.equals ("BUFFER_UNDERFLOW"))
	return BUFFER_UNDERFLOW;
      if (name.equals ("BUFFER_OVERFLOW"))
	return BUFFER_OVERFLOW;
      if (name.equals ("OK"))
	return OK;
      if (name.equals ("CLOSED"))
	return CLOSED;
      throw new IllegalArgumentException (name);
    }
  }

  /**
   * An enumeration of possible handshake status states.
   */
  public static class HandshakeStatus extends PseudoEnum // FIXME ENUM 1.5
  {

    /**
     * Not currently handshaking.
     */
    public static final HandshakeStatus NOT_HANDSHAKING = new HandshakeStatus (0, "NOT_HANDSHAKING");

    /**
     * The handshake is finished.
     */
    public static final HandshakeStatus FINISHED = new HandshakeStatus (1, "FINISHED");

    /**
     * Needs the status of one or more delegated tasks.
     */
    public static final HandshakeStatus NEED_TASK = new HandshakeStatus (2, "NEED_TASK");

    /**
     * Has data prepared for output, and needs a new call to
     * <code>wrap</code>.
     */
    public static final HandshakeStatus NEED_WRAP = new HandshakeStatus (3, "NEED_WRAP");

    /**
     * Is waiting for more input.
     */
    public static final HandshakeStatus NEED_UNWRAP = new HandshakeStatus (4, "NEED_UNWRAP");

    private HandshakeStatus (final int ordinal, final String name)
    {
      super (ordinal, name, HandshakeStatus.class);
    }

    public static HandshakeStatus[] values ()
    {
      return new HandshakeStatus[] { NOT_HANDSHAKING, FINISHED, NEED_TASK,
				     NEED_WRAP, NEED_UNWRAP };
    }

    public static HandshakeStatus valueOf (final String name)
    {
      if (name.equals ("NOT_HANDSHAKING"))
	return NOT_HANDSHAKING;
      if (name.equals ("FINISHED"))
	return FINISHED;
      if (name.equals ("NEED_TASK"))
	return NEED_TASK;
      if (name.equals ("NEED_WRAP"))
	return NEED_WRAP;
      if (name.equals ("NEED_UNWRAP"))
	return NEED_UNWRAP;
      throw new IllegalArgumentException (name);
    }
  }



  /**
   * Returns the number of bytes consumed by the previous operation.
   *
   * @return The number of bytes consumed.
   */
  public int bytesConsumed ()
  {
    return bytesConsumed;
  }

  /**
   * Returns the number of bytes produced by the previous operation.
   *
   * @return The number of bytes produced.
   */
  public int bytesProduced ()
  {
    return bytesProduced;
  }

  /**
   * Returns the handshake status.
   *
   * @return The handshake status.
   */
  public HandshakeStatus getHandshakeStatus ()
  {
    return handshakeStatus;
  }

  /**
   * Returns the connection status.
   *
   * @return The connection status.
   */
  public Status getStatus ()
  {
    return status;
  }

  public String toString ()
  {
    return (super.toString () + " [ status: " + status + "; handshakeStatus: "
	    + handshakeStatus + "; bytesConsumed: " + bytesConsumed
	    + "; bytesProduced: " + bytesProduced + " ]");
  }
}
