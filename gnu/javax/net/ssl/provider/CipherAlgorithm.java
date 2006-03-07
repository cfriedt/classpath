/* CipherAlgorithm.java -- Cipher algorithm enumeration.
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

class CipherAlgorithm implements Enumerated
{
  private static final int NULL_VALUE   = 0;
  private static final int RC4_VALUE    = 1;
  private static final int DES_VALUE    = 2;
  private static final int DESede_VALUE = 3;
  private static final int CAST5_VALUE  = 4;
  private static final int AES_VALUE    = 5;

  static final CipherAlgorithm NULL   = new CipherAlgorithm (NULL_VALUE);
  static final CipherAlgorithm RC4    = new CipherAlgorithm (RC4_VALUE);
  static final CipherAlgorithm DES    = new CipherAlgorithm (DES_VALUE);
  static final CipherAlgorithm DESede = new CipherAlgorithm (DESede_VALUE);
  static final CipherAlgorithm CAST5  = new CipherAlgorithm (CAST5_VALUE);
  static final CipherAlgorithm AES    = new CipherAlgorithm (AES_VALUE);

  private final int value;

  private CipherAlgorithm (final int value)
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
      case NULL_VALUE:   return "NULL";
      case RC4_VALUE:    return "RC4";
      case DES_VALUE:    return "DES";
      case DESede_VALUE: return "DESede";
      case CAST5_VALUE:  return "CAST5";
      case AES_VALUE:    return "AES";
     }
    return "unknown (" + value + ")";
  }
}
