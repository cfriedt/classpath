/* CipherSuite.java -- Supported cipher suites.
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

import gnu.java.security.action.GetSecurityPropertyAction;

import java.io.IOException;
import java.io.OutputStream;

import java.nio.ByteBuffer;

import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.NullCipher;

public final class CipherSuite implements Constructed
{

  // Constants and fields.
  // -------------------------------------------------------------------------

  private static final List<String> tlsSuiteNames = new LinkedList<String>();
  private static final HashMap<String, CipherSuite> namesToSuites = new HashMap<String, CipherSuite>();

  // SSL CipherSuites.
  public static final CipherSuite SSL_NULL_WITH_NULL_NULL =
    new CipherSuite (CipherAlgorithm.NULL,
                     KeyExchangeAlgorithm.NONE,
                     SignatureAlgorithm.ANONYMOUS,
                     MacAlgorithm.NULL, 0, 0x00, 0x00,
                     "SSL_NULL_WITH_NULL_NULL",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_WITH_NULL_MD5 =
    new CipherSuite (CipherAlgorithm.NULL,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_MD5, 0, 0x00, 0x01,
                     "SSL_RSA_WITH_NULL_MD5",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_WITH_NULL_SHA =
    new CipherSuite (CipherAlgorithm.NULL,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 0, 0x00, 0x02,
                     "SSL_RSA_WITH_NULL_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_EXPORT_WITH_RC4_40_MD5 =
    new CipherSuite (CipherAlgorithm.RC4,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_MD5, 5, 0x00, 0x03,
                     "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_WITH_RC4_128_MD5 =
    new CipherSuite (CipherAlgorithm.RC4,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_MD5, 16, 0x00, 0x04,
                     "SSL_RSA_WITH_RC4_128_MD5",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_WITH_RC4_128_SHA =
    new CipherSuite (CipherAlgorithm.RC4,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 16, 0x00, 0x05,
                     "SSL_RSA_WITH_RC4_128_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_EXPORT_WITH_DES40_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 5, 0x00, 0x08,
                     "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_WITH_DES_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 8, 0x00, 0x09,
                     "SSL_RSA_WITH_DES_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 24, 0x00, 0x0A,
                     "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.SSLMAC_SHA, 5, 0x00, 0x0B,
                     "SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DH_DSS_WITH_DES_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.SSLMAC_SHA, 8, 0x00, 0x0C,
                     "SSL_DH_DSS_WITH_DES_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.SSLMAC_SHA, 24, 0x00, 0x0D,
                     "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 5, 0x00, 0x0E,
                     "SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DH_RSA_WITH_DES_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 8, 0x00, 0x0F,
                     "SSL_DH_RSA_WITH_DES_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 24, 0x00, 0x10,
                     "SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.SSLMAC_SHA, 5, 0x00, 0x11,
                     "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_DSS_WITH_DES_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.SSLMAC_SHA, 8, 0x00, 0x12,
                     "SSL_DHE_DSS_WITH_DES_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.SSLMAC_SHA, 24, 0x00, 0x13,
                     "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 5, 0x00, 0x14,
                     "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_RSA_WITH_DES_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 8, 0x00, 0x15,
                     "SSL_DHE_RSA_WITH_DES_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 24, 0x00, 0x16,
                     "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.SSL_3);

  // AES CipherSuites.
  public static final CipherSuite SSL_RSA_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 16, 0x00, 0x2F,
                    "SSL_RSA_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DH_DSS_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.SSLMAC_SHA, 16, 0x00, 0x30,
                     "SSL_DH_DSS_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DH_RSA_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 16, 0x00, 0x31,
                    "SSL_DH_RSA_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_DSS_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.SSLMAC_SHA, 16, 0x00, 0x32,
                    "SSL_DHE_DSS_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_RSA_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 16, 0x00, 0x33,
                    "SSL_DHE_RSA_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 32, 0x00, 0x35,
                    "SSL_RSA_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DH_DSS_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.SSLMAC_SHA, 32, 0x00, 0x36,
                     "SSL_DH_DSS_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DH_RSA_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 32, 0x00, 0x37,
                    "SSL_DH_RSA_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_DSS_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.SSLMAC_SHA, 32, 0x00, 0x38,
                    "SSL_DHE_DSS_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_RSA_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.SSLMAC_SHA, 32, 0x00, 0x39,
                     "SSL_DHE_RSA_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.SSL_3);

  // Ciphersuites from the OpenPGP extension draft.
  public static final CipherSuite SSL_DHE_DSS_WITH_CAST_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.CAST5,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x70,
                     "SSL_DHE_DSS_WITH_CAST_128_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_DSS_WITH_CAST_128_CBC_RMD =
    new CipherSuite (CipherAlgorithm.CAST5,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_RMD, 16, 0x00, 0x71,
                     "SSL_DHE_DSS_WITH_CAST_128_CBC_RMD",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_DSS_WITH_3DES_EDE_CBC_RMD =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_RMD, 24, 0x00, 0x72,
                     "SSL_DHE_DSS_WITH_3DES_EDE_CBC_RMD",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_DSS_WITH_AES_128_CBC_RMD =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_RMD, 16, 0x00, 0x73,
                     "SSL_DHE_DSS_WITH_AES_128_CBC_RMD",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_DSS_WITH_AES_256_CBC_RMD =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_RMD, 32, 0x00, 0x74,
                     "SSL_DHE_DSS_WITH_AES_256_CBC_RMD",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_RSA_WITH_CAST_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.CAST5,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x75,
                     "SSL_DHE_RSA_WITH_CAST_128_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_RSA_WITH_CAST_128_CBC_RMD =
    new CipherSuite (CipherAlgorithm.CAST5,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 16, 0x00, 0x76,
                     "SSL_DHE_RSA_WITH_CAST_128_CBC_RMD",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_RSA_WITH_3DES_EDE_CBC_RMD =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 24, 0x00, 0x77,
                     "SSL_DHE_RSA_WITH_3DES_EDE_CBC_RMD",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_RSA_WITH_AES_128_CBC_RMD =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 16, 0x00, 0x78,
                     "SSL_DHE_RSA_WITH_AES_128_CBC_RMD",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_DHE_RSA_WITH_AES_256_CBC_RMD =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 32, 0x00, 0x79,
                     "SSL_DHE_RSA_WITH_AES_256_CBC_RMD",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_WITH_CAST_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.CAST5,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x7A,
                     "SSL_RSA_WITH_CAST_128_CBC_SHA",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_WITH_CAST_128_CBC_RMD =
    new CipherSuite (CipherAlgorithm.CAST5,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 16, 0x00, 0x7B,
                     "SSL_RSA_WITH_CAST_128_CBC_RMD",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_WITH_3DES_EDE_CBC_RMD =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 24, 0x00, 0x7C,
                     "SSL_RSA_WITH_3DES_EDE_CBC_RMD",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_WITH_AES_128_CBC_RMD =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 16, 0x00, 0x7D,
                     "SSL_RSA_WITH_AES_128_CBC_RMD",
                     ProtocolVersion.SSL_3);
  public static final CipherSuite SSL_RSA_WITH_AES_256_CBC_RMD =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 32, 0x00, 0x7E,
                     "SSL_RSA_WITH_AES_256_CBC_RMD",
                     ProtocolVersion.SSL_3);

  public static final CipherSuite TLS_NULL_WITH_NULL_NULL =
    new CipherSuite (CipherAlgorithm.NULL,
                     KeyExchangeAlgorithm.NONE,
                     SignatureAlgorithm.ANONYMOUS,
                     MacAlgorithm.NULL, 0, 0x00, 0x00,
                     "TLS_NULL_WITH_NULL_NULL",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_WITH_NULL_MD5 =
    new CipherSuite (CipherAlgorithm.NULL,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_MD5, 0, 0x00, 0x01,
                     "TLS_RSA_WITH_NULL_MD5",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_WITH_NULL_SHA =
    new CipherSuite (CipherAlgorithm.NULL,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 0, 0x00, 0x02,
                     "TLS_RSA_WITH_NULL_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_EXPORT_WITH_RC4_40_MD5 =
    new CipherSuite (CipherAlgorithm.RC4,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_MD5, 5, 0x00, 0x03,
                     "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_WITH_RC4_128_MD5 =
    new CipherSuite (CipherAlgorithm.RC4,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_MD5, 16, 0x00, 0x04,
                     "TLS_RSA_WITH_RC4_128_MD5",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_WITH_RC4_128_SHA =
    new CipherSuite (CipherAlgorithm.RC4,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x05,
                     "TLS_RSA_WITH_RC4_128_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_EXPORT_WITH_DES40_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 5, 0x00, 0x08,
                     "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_WITH_DES_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 8, 0x00, 0x09,
                     "TLS_RSA_WITH_DES_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 24, 0x00, 0x0A,
                     "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 5, 0x00, 0x0B,
                     "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DH_DSS_WITH_DES_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 8, 0x00, 0x0C,
                     "TLS_DH_DSS_WITH_DES_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 24, 0x00, 0x0D,
                     "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 5, 0x00, 0x0E,
                     "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DH_RSA_WITH_DES_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 8, 0x00, 0x0F,
                     "TLS_DH_RSA_WITH_DES_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 24, 0x00, 0x10,
                     "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 5, 0x00, 0x11,
                     "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_DSS_WITH_DES_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 8, 0x00, 0x12,
                     "TLS_DHE_DSS_WITH_DES_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 24, 0x00, 0x13,
                     "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 5, 0x00, 0x14,
                     "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_RSA_WITH_DES_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 8, 0x00, 0x15,
                     "TLS_DHE_RSA_WITH_DES_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 24, 0x00, 0x16,
                     "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.TLS_1);

  // AES CipherSuites.
  public static final CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x2F,
                     "TLS_RSA_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x30,
                     "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x31,
                     "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x32,
                     "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x33,
                     "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 32, 0x00, 0x35,
                     "TLS_RSA_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 32, 0x00, 0x36,
                     "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 32, 0x00, 0x37,
                     "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 32, 0x00, 0x38,
                     "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 32, 0x00, 0x39,
                     "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.TLS_1);

  // Secure remote password (SRP) ciphersuites
  public static final CipherSuite TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.SRP,
                     SignatureAlgorithm.ANONYMOUS,
                     MacAlgorithm.HMAC_SHA, 24, 0x00, 0x50,
                     "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.SRP,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 24, 0x00, 0x51,
                     "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.SRP,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 24, 0x00, 0x52,
                     "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_SRP_SHA_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.SRP,
                     SignatureAlgorithm.ANONYMOUS,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x53,
                     "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.SRP,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x54,
                     "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.SRP,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x55,
                     "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_SRP_SHA_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.SRP,
                     SignatureAlgorithm.ANONYMOUS,
                     MacAlgorithm.HMAC_SHA, 32, 0x00, 0x56,
                     "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.SRP,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 32, 0x00, 0x57,
                     "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.SRP,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 32, 0x00, 0x58,
                     "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
                     ProtocolVersion.TLS_1);

  // Ciphersuites from the OpenPGP extension draft.
  public static final CipherSuite TLS_DHE_DSS_WITH_CAST_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.CAST5,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x70,
                     "TLS_DHE_DSS_WITH_CAST_128_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_DSS_WITH_CAST_128_CBC_RMD =
    new CipherSuite (CipherAlgorithm.CAST5,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_RMD, 16, 0x00, 0x71,
                     "TLS_DHE_DSS_WITH_CAST_128_CBC_RMD",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_RMD, 24, 0x00, 0x72,
                     "TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_RMD =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_RMD, 16, 0x00, 0x73,
                     "TLS_DHE_DSS_WITH_AES_128_CBC_RMD",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_RMD =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.DSA,
                     MacAlgorithm.HMAC_RMD, 32, 0x00, 0x74,
                     "TLS_DHE_DSS_WITH_AES_256_CBC_RMD",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_RSA_WITH_CAST_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.CAST5,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x75,
                     "TLS_DHE_RSA_WITH_CAST_128_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_RSA_WITH_CAST_128_CBC_RMD =
    new CipherSuite (CipherAlgorithm.CAST5,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 16, 0x00, 0x76,
                     "TLS_DHE_RSA_WITH_CAST_128_CBC_RMD",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 24, 0x00, 0x77,
                     "TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_RMD =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 16, 0x00, 0x78,
                     "TLS_DHE_RSA_WITH_AES_128_CBC_RMD",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_RMD =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.DIFFIE_HELLMAN, true,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 32, 0x00, 0x79,
                     "TLS_DHE_RSA_WITH_AES_256_CBC_RMD",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_WITH_CAST_128_CBC_SHA =
    new CipherSuite (CipherAlgorithm.CAST5,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_SHA, 16, 0x00, 0x7A,
                     "TLS_RSA_WITH_CAST_128_CBC_SHA",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_WITH_CAST_128_CBC_RMD =
    new CipherSuite (CipherAlgorithm.CAST5,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 16, 0x00, 0x7B,
                     "TLS_RSA_WITH_CAST_128_CBC_RMD",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_RMD =
    new CipherSuite (CipherAlgorithm.DESede,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 24, 0x00, 0x7C,
                     "TLS_RSA_WITH_3DES_EDE_CBC_RMD",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_WITH_AES_128_CBC_RMD =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 16, 0x00, 0x7D,
                     "TLS_RSA_WITH_AES_128_CBC_RMD",
                     ProtocolVersion.TLS_1);
  public static final CipherSuite TLS_RSA_WITH_AES_256_CBC_RMD =
    new CipherSuite (CipherAlgorithm.AES,
                     KeyExchangeAlgorithm.RSA,
                     SignatureAlgorithm.RSA,
                     MacAlgorithm.HMAC_RMD, 32, 0x00, 0x7E,
                     "TLS_RSA_WITH_AES_256_CBC_RMD",
                     ProtocolVersion.TLS_1);

  private final CipherAlgorithm cipherAlgorithm;
  private final KeyExchangeAlgorithm keyExchangeAlgorithm;
  private final SignatureAlgorithm signatureAlgorithm;
  private final MacAlgorithm macAlgorithm;
  private final boolean ephemeralDH;
  private final boolean exportable;
  private final boolean isStream;
  private final int keyLength;
  private final byte[] id;
  private final String name;
  private final ProtocolVersion version;

  // Constructors.
  // -------------------------------------------------------------------------

  private CipherSuite (final CipherAlgorithm cipherAlgorithm,
                       final KeyExchangeAlgorithm keyExchangeAlgorithm,
                       final SignatureAlgorithm signatureAlgorithm,
                       final MacAlgorithm macAlgorithm,
                       final int keyLength,
                       final int id1,
                       final int id2,
                       final String name,
                       final ProtocolVersion version)
  {
    this (cipherAlgorithm, keyExchangeAlgorithm, false, signatureAlgorithm,
          macAlgorithm, keyLength, id1, id2, name, version);
  }

  private CipherSuite (final CipherAlgorithm cipherAlgorithm,
                       final KeyExchangeAlgorithm keyExchangeAlgorithm,
                       final boolean ephemeralDH,
                       final SignatureAlgorithm signatureAlgorithm,
                       final MacAlgorithm macAlgorithm,
                       final int keyLength,
                       final int id1,
                       final int id2,
                       final String name,
                       final ProtocolVersion version)
  {
    this.cipherAlgorithm = cipherAlgorithm;
    this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    this.ephemeralDH = ephemeralDH;
    this.signatureAlgorithm = signatureAlgorithm;
    this.macAlgorithm = macAlgorithm;
    this.exportable = keyLength <= 5;
    this.isStream = (cipherAlgorithm == CipherAlgorithm.NULL
                     || cipherAlgorithm == CipherAlgorithm.RC4);
    this.keyLength = keyLength;
    this.id = new byte[] { (byte) id1, (byte) id2 };
    this.name = name.intern();
    this.version = version;
    namesToSuites.put(name, this);
    if (name.startsWith("TLS"))
      {
        tlsSuiteNames.add(name);
      }
  }

  private CipherSuite(byte[] id)
  {
    cipherAlgorithm = null;
    keyExchangeAlgorithm = null;
    signatureAlgorithm = null;
    macAlgorithm = null;
    ephemeralDH = false;
    exportable = false;
    isStream = false;
    keyLength = 0;
    this.id = id;
    name = null;
    version = null;
  }

  // Class methods.
  // -------------------------------------------------------------------------

  /**
   * Returns the cipher suite for the given name, or null if there is no
   * such suite.
   *
   * @return The named cipher suite.
   */
  public static CipherSuite forName(String name)
  {
    return (CipherSuite) namesToSuites.get (name);
  }

  public static CipherSuite forValue (final short raw_value)
  {
    byte[] b = new byte[] { (byte) (raw_value >>> 8), (byte) raw_value };
    return new CipherSuite (b);
  }

  public static CipherSuite forValue (final short raw_value, final ProtocolVersion version)
  {
    return forValue (raw_value).resolve (version);
  }

  public static List availableSuiteNames()
  {
    return tlsSuiteNames;
  }

  // Intance methods.
  // -------------------------------------------------------------------------

  public CipherAlgorithm cipherAlgorithm ()
  {
    return cipherAlgorithm;
  }

  public Cipher cipher () throws NoSuchAlgorithmException, NoSuchPaddingException
  {
    if (cipherAlgorithm == null)
      throw new NoSuchAlgorithmException (toString () + ": unresolved cipher suite");
    if (cipherAlgorithm == CipherAlgorithm.NULL)
      return new NullCipher ();

    String alg = null;
    if (cipherAlgorithm == CipherAlgorithm.RC4)
      alg = "RC4";
    else
      alg = cipherAlgorithm + "/CBC/NoPadding";
    GetSecurityPropertyAction gspa =
      new GetSecurityPropertyAction ("jessie.jce.provider");
    final String provider = (String) AccessController.doPrivileged (gspa);
    if (provider != null)
      {
        try
          {
            return Cipher.getInstance (alg, provider);
          }
        catch (NoSuchProviderException nspe)
          {
          }
      }
    return Cipher.getInstance (alg);
  }

  public MacAlgorithm getMacAlgorithm ()
  {
    return macAlgorithm;
  }

  public Mac mac () throws NoSuchAlgorithmException
  {
    if (macAlgorithm == null)
      throw new NoSuchAlgorithmException (toString () + ": unresolved cipher suite");
    if (macAlgorithm == MacAlgorithm.NULL)
      return null;
    GetSecurityPropertyAction gspa =
      new GetSecurityPropertyAction ("jessie.jce.provider");
    final String provider = (String) AccessController.doPrivileged (gspa);
    if (provider != null)
      {
        try
          {
            return Mac.getInstance (macAlgorithm.toString (), provider);
          }
        catch (NoSuchProviderException nspe)
          {
          }
      }
    return Mac.getInstance (macAlgorithm.toString ());
  }

  public SignatureAlgorithm signatureAlgorithm ()
  {
    return signatureAlgorithm;
  }

  public KeyExchangeAlgorithm keyExchangeAlgorithm ()
  {
    return keyExchangeAlgorithm;
  }

  public boolean isEphemeralDH ()
  {
    return ephemeralDH;
  }

  public int length ()
  {
    return 2;
  }

  public void write(OutputStream out) throws IOException
  {
    out.write(id);
  }

  public void put (final ByteBuffer buf)
  {
    buf.put (id);
  }

  public boolean isResolved ()
  {
    return (version != null);
  }

  public CipherSuite resolve(ProtocolVersion version)
  {
    if (version == ProtocolVersion.SSL_3)
      {
        if (id[0] == 0x00) switch (id[1])
          {
          case 0x00: return SSL_NULL_WITH_NULL_NULL;
          case 0x01: return SSL_RSA_WITH_NULL_MD5;
          case 0x02: return SSL_RSA_WITH_NULL_SHA;
          case 0x03: return SSL_RSA_EXPORT_WITH_RC4_40_MD5;
          case 0x04: return SSL_RSA_WITH_RC4_128_MD5;
          case 0x05: return SSL_RSA_WITH_RC4_128_SHA;
          case 0x08: return SSL_RSA_EXPORT_WITH_DES40_CBC_SHA;
          case 0x09: return SSL_RSA_WITH_DES_CBC_SHA;
          case 0x0A: return SSL_RSA_WITH_3DES_EDE_CBC_SHA;
          case 0x0B: return SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA;
          case 0x0C: return SSL_DH_DSS_WITH_DES_CBC_SHA;
          case 0x0D: return SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA;
          case 0x0E: return SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA;
          case 0x0F: return SSL_DH_RSA_WITH_DES_CBC_SHA;
          case 0x10: return SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA;
          case 0x11: return SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA;
          case 0x12: return SSL_DHE_DSS_WITH_DES_CBC_SHA;
          case 0x13: return SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA;
          case 0x14: return SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA;
          case 0x15: return SSL_DHE_RSA_WITH_DES_CBC_SHA;
          case 0x16: return SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA;
          case 0x2F: return SSL_RSA_WITH_AES_128_CBC_SHA;
          case 0x30: return SSL_DH_DSS_WITH_AES_128_CBC_SHA;
          case 0x31: return SSL_DH_RSA_WITH_AES_128_CBC_SHA;
          case 0x32: return SSL_DHE_DSS_WITH_AES_128_CBC_SHA;
          case 0x33: return SSL_DHE_RSA_WITH_AES_128_CBC_SHA;
          case 0x35: return SSL_RSA_WITH_AES_256_CBC_SHA;
          case 0x36: return SSL_DH_DSS_WITH_AES_256_CBC_SHA;
          case 0x37: return SSL_DH_RSA_WITH_AES_256_CBC_SHA;
          case 0x38: return SSL_DHE_DSS_WITH_AES_256_CBC_SHA;
          case 0x39: return SSL_DHE_RSA_WITH_AES_256_CBC_SHA;
          }
      }
    else if (version == ProtocolVersion.TLS_1 ||
             version == ProtocolVersion.TLS_1_1)
      {
        if (id[0] == 0x00) switch (id[1])
          {
          case 0x00: return TLS_NULL_WITH_NULL_NULL;
          case 0x01: return TLS_RSA_WITH_NULL_MD5;
          case 0x02: return TLS_RSA_WITH_NULL_SHA;
          case 0x03: return TLS_RSA_EXPORT_WITH_RC4_40_MD5;
          case 0x04: return TLS_RSA_WITH_RC4_128_MD5;
          case 0x05: return TLS_RSA_WITH_RC4_128_SHA;
          case 0x08: return TLS_RSA_EXPORT_WITH_DES40_CBC_SHA;
          case 0x09: return TLS_RSA_WITH_DES_CBC_SHA;
          case 0x0A: return TLS_RSA_WITH_3DES_EDE_CBC_SHA;
          case 0x0B: return TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA;
          case 0x0C: return TLS_DH_DSS_WITH_DES_CBC_SHA;
          case 0x0D: return TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA;
          case 0x0E: return TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA;
          case 0x0F: return TLS_DH_RSA_WITH_DES_CBC_SHA;
          case 0x10: return TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA;
          case 0x11: return TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA;
          case 0x12: return TLS_DHE_DSS_WITH_DES_CBC_SHA;
          case 0x13: return TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA;
          case 0x14: return TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA;
          case 0x15: return TLS_DHE_RSA_WITH_DES_CBC_SHA;
          case 0x16: return TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA;
          case 0x2F: return TLS_RSA_WITH_AES_128_CBC_SHA;
          case 0x30: return TLS_DH_DSS_WITH_AES_128_CBC_SHA;
          case 0x31: return TLS_DH_RSA_WITH_AES_128_CBC_SHA;
          case 0x32: return TLS_DHE_DSS_WITH_AES_128_CBC_SHA;
          case 0x33: return TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
          case 0x35: return TLS_RSA_WITH_AES_256_CBC_SHA;
          case 0x36: return TLS_DH_DSS_WITH_AES_256_CBC_SHA;
          case 0x37: return TLS_DH_RSA_WITH_AES_256_CBC_SHA;
          case 0x38: return TLS_DHE_DSS_WITH_AES_256_CBC_SHA;
          case 0x39: return TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
          case 0x50: return TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA;
          case 0x51: return TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA;
          case 0x52: return TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA;
          case 0x53: return TLS_SRP_SHA_WITH_AES_128_CBC_SHA;
          case 0x54: return TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA;
          case 0x55: return TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA;
          case 0x56: return TLS_SRP_SHA_WITH_AES_256_CBC_SHA;
          case 0x57: return TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA;
          case 0x58: return TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA;
          case 0x70: return TLS_DHE_DSS_WITH_CAST_128_CBC_SHA;
          case 0x71: return TLS_DHE_DSS_WITH_CAST_128_CBC_RMD;
          case 0x72: return TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD;
          case 0x73: return TLS_DHE_DSS_WITH_AES_128_CBC_RMD;
          case 0x74: return TLS_DHE_DSS_WITH_AES_256_CBC_RMD;
          case 0x75: return TLS_DHE_RSA_WITH_CAST_128_CBC_SHA;
          case 0x76: return TLS_DHE_RSA_WITH_CAST_128_CBC_RMD;
          case 0x77: return TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD;
          case 0x78: return TLS_DHE_RSA_WITH_AES_128_CBC_RMD;
          case 0x79: return TLS_DHE_RSA_WITH_AES_256_CBC_RMD;
          case 0x7A: return TLS_RSA_WITH_CAST_128_CBC_SHA;
          case 0x7B: return TLS_RSA_WITH_CAST_128_CBC_RMD;
          case 0x7C: return TLS_RSA_WITH_3DES_EDE_CBC_RMD;
          case 0x7D: return TLS_RSA_WITH_AES_128_CBC_RMD;
          case 0x7E: return TLS_RSA_WITH_AES_256_CBC_RMD;
          }
      }
    return this;
  }

  public int keyLength()
  {
    return keyLength;
  }

  public boolean isExportable()
  {
    return exportable;
  }

  public boolean isStreamCipher()
  {
    return isStream;
  }

//   String getAuthType()
//   {
//     if (keyExchangeAlgorithm == KeyExchangeAlgorithm.RSA)
//       {
//         if (isExportable())
//           {
//             return "RSA_EXPORT";
//           }
//         return "RSA";
//       }
//     return kexName + "_" + sigName;
//   }

  public byte[] id()
  {
    return id;
  }

  public ProtocolVersion version()
  {
    return version;
  }

  public boolean equals(Object o)
  {
    if (!(o instanceof CipherSuite))
      {
        return false;
      }
    if (o == this)
      return true;
    byte[] id = ((CipherSuite) o).id();
    return (id[0] == this.id[0] &&
            id[1] == this.id[1]);
  }

  public int hashCode()
  {
    if (version == null)
      {
        return 0xFFFF0000 | (id[0] & 0xFF) << 8 | (id[1] & 0xFF);
      }
    return (version.major() << 24 | version.minor() << 16
            | (id[0] & 0xFF) << 8 | (id[1] & 0xFF));
  }

  public String toString (String prefix)
  {
    return toString ();
  }

  public String toString()
  {
    if (name == null)
      {
        return "{ " + (id[0] & 0xFF) + ", " + (id[1] & 0xFF) + " }";
      }
    return name;
  }
}
