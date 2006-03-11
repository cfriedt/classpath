/* PseudoEnum.java -- emulate an Enum in pre-Java 1.5 code.
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


package gnu.java.lang;

import java.io.Serializable;

public abstract class PseudoEnum implements Comparable, Serializable
{
  private final int ordinal;
  private final String name;
  private final Class declaringClass;

  protected PseudoEnum (final int ordinal, final String name,
                        final Class declaringClass)
  {
    this.ordinal = ordinal;
    this.name = name;
    this.declaringClass = declaringClass;
  }

  public final int compareTo (Object o)
  {
    PseudoEnum that = (PseudoEnum) o;
    if (ordinal < that.ordinal)
      return -1;
    if (ordinal > that.ordinal)
      return 1;
    return 0;
  }

  public final boolean equals (Object o)
  {
    return (this == o);
  }

  public final Class getDeclaringClass ()
  {
    return declaringClass;
  }

  public final int hashCode ()
  {
    return ordinal;
  }

  public final String name ()
  {
    return name;
  }

  public final int ordinal ()
  {
    return ordinal;
  }

  public String toString ()
  {
    return name;
  }
}
