/* SessionStore.java -- stores SSL sessions, possibly persistently.
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


package gnu.javax.net.ssl;

import javax.net.ssl.SSLPermission;

public abstract class SessionStore
{

  protected final long timeout;
  private static SessionStore globalInstance; // = XXX default impl.

  public static SessionStore globalInstance ()
  {
    SecurityManager sm = System.getSecurityManager ();
    if (sm != null)
      sm.checkPermission (new SSLPermission ("gnu.javax.net.ssl.SessionStore",
                                             "getGlobalInstance"));
    return globalInstance;
  }

  public static void setGlobalInstance (SessionStore store)
  {
    SecurityManager sm = System.getSecurityManager ();
    if (sm != null)
      sm.checkPermission (new SSLPermission ("gnu.javax.net.ssl.SessionStore",
                                             "setGlobalInstance"));
    globalInstance = store;
  }

  protected SessionStore (final long timeout)
  {
    this.timeout = timeout;
  }

  /**
   * Fetch a saved session by its ID. This method will (possibly)
   * deserialize and return the SSL session with that ID, or null if
   * the requested session does not exist, or has expired.
   *
   * <p>Subclasses implementing this class <strong>must not</strong>
   * perform any blocking operations in this method. If any blocking
   * behavior is required, it must be done in the {@link load(char[])}
   * method.
   *
   * @param sessionId The ID of the session to get.
   * @return The found session, or null if no such session was found,
   * or if that session has expired.
   */
  public final Session get (Session.ID sessionId)
  {
    Session s = implGet (sessionId);
    if (System.currentTimeMillis () - s.getLastAccessedTime () > timeout)
      {
        remove (sessionId);
        return null;
      }
    return s;
  }
  
  protected abstract Session implGet (Session.ID sessionId);

  /**
   * Load this session store from the underlying media, if supported
   * by the implementation.
   *
   * @param password The password that protects the sensitive data in
   * this store.
   * @throws SessionStoreException If reading this store fails, such
   * as when an I/O exception occurs, or if the password is incorrect.
   */
  public abstract void load (char[] password) throws SessionStoreException;

  /**
   * Add a new session to the store. The underlying implementation
   * will add the session to its store, possibly overwriting any
   * existing session with the same ID.
   *
   * <p>Subclasses implementing this class <strong>must not</strong>
   * perform any blocking operations in this method. If any blocking
   * behavior is required, it must be done in the {@link
   * #store(char[])} method.
   *
   * @param session The session to add.
   * @throws NullPointerException If the argument is null.
   */
  public abstract void put (Session session);

  /**
   * Remove a session from this store.
   *
   * <p>Subclasses implementing this class <strong>must not</strong>
   * perform any blocking operations in this method. If any blocking
   * behavior is required, it must be done in the {@link
   * #store(char[])} method.
   *
   * @param sessionId The ID of the session to remove.
   */
  public abstract void remove (Session.ID sessionId);

  /**
   * Commit this session store to the underlying media. For session
   * store implementations that support saving sessions across
   * invocations of the JVM, this method will save any sessions that
   * have not expired to some persistent media, so they may be loaded
   * and used again later.
   *
   * @param password The password that will protect the sensitive data
   * in this store.
   */
  public abstract void store (char[] password) throws SessionStoreException;
}