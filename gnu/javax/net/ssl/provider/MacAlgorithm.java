/* MacAlgorithm.java -- MAC algorithm enumeration.
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

class MacAlgorithm implements Enumerated
{
  private static final int NULL_VALUE       = -1;
  private static final int SSLMAC_MD5_VALUE = 0;
  private static final int SSLMAC_SHA_VALUE = 1;
  private static final int HMAC_MD5_VALUE   = 2;
  private static final int HMAC_SHA_VALUE   = 3;
  private static final int HMAC_RMD_VALUE   = 4;

  static final MacAlgorithm NULL       = new MacAlgorithm (NULL_VALUE);
  static final MacAlgorithm SSLMAC_MD5 = new MacAlgorithm (SSLMAC_MD5_VALUE);
  static final MacAlgorithm SSLMAC_SHA = new MacAlgorithm (SSLMAC_SHA_VALUE);
  static final MacAlgorithm HMAC_MD5   = new MacAlgorithm (HMAC_MD5_VALUE);
  static final MacAlgorithm HMAC_SHA   = new MacAlgorithm (HMAC_SHA_VALUE);
  static final MacAlgorithm HMAC_RMD   = new MacAlgorithm (HMAC_RMD_VALUE);

  private final int value;

  private MacAlgorithm (final int value)
  {
    this.value = value;
  }

  public byte[] getEncoded ()
  {
    throw new UnsupportedOperationException ();
  }

  public int getValue ()
  {
    return value;
  }

  public String toString ()
  {
    switch (value)
      {
      case NULL_VALUE: return "NULL";
      case SSLMAC_MD5_VALUE: return "SSLMAC-MD5";
      case SSLMAC_SHA_VALUE: return "SSLMAC-SHA";
      case HMAC_MD5_VALUE: return "HMAC-MD5";
      case HMAC_SHA_VALUE: return "HMAC-SHA";
      case HMAC_RMD_VALUE: return "HMAC-RIPEMD-160";
      }
    return "unknown (" + value + ")";
  }
}
