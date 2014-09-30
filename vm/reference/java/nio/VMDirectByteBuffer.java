/* VMDirectByteBuffer.java --
   Copyright (C) 2004, 2010  Free Software Foundation, Inc.

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
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301 USA.

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


package java.nio;

import java.lang.reflect.*;
import java.util.*;

import sun.misc.*;
import gnu.classpath.*;

final class VMDirectByteBuffer
{

  static
  {
    // load the shared library needed for native methods.
    if (Configuration.INIT_LOAD_LIBRARY)
      {
        System.loadLibrary("javanio");
      }
  }

  private VMDirectByteBuffer() {} // Prohibits instantiation.

  private static final Unsafe unsafe = Unsafe.getUnsafe();
  private static class JamArrayObjectInfo {
    static final int size_idx = 2;
    static final int data_ptr_idx = 3;
    static final int size_offset = unsafe.addressSize() * size_idx; 
    static final int data_ptr_offset = unsafe.addressSize() * data_ptr_idx; 
  };
  private static Field ptr32data;
  private static Field ptr64data;
  private static long getNativePointer( Pointer ptr ) {
    long r = -1;
    Exception e2 = null;
    try {
      if ( 4 == unsafe.addressSize() ) {
        if ( null == ptr32data ) {
          ptr32data =  Pointer32.class.getDeclaredField("data");
          ptr32data.setAccessible( true );
        }
        r = ptr32data.getInt( ptr );
      } else if ( 8 == unsafe.addressSize() ) {
        if ( null == ptr64data ) {
          ptr64data =  Pointer64.class.getDeclaredField("data");
          ptr64data.setAccessible( true );
        }
        r = ptr64data.getLong( ptr );
      }
    } catch (IllegalAccessException e ) {
      e2 = e;
    } catch (NoSuchFieldException e) {
      e2 = e;
    }
    if ( null != e2 ) {
      IllegalStateException ex = new IllegalStateException( "failed to find native pointer field in pointer class" );
      ex.setStackTrace( e2.getStackTrace() );
      throw ex;
    }
    return r;
  }
  private static final HashMap<String,Class<?>> class_map = new HashMap<String,Class<?>>();
  static {
    class_map.put( "[Z", boolean[].class );
    class_map.put( "[B", byte[].class );
    class_map.put( "[C", char[].class );
    class_map.put( "[S", short[].class );
    class_map.put( "[I", int[].class );
    class_map.put( "[J", long[].class );
    class_map.put( "[F", float[].class );
    class_map.put( "[D", double[].class );
  }
  
  static Object pointerToArray(Pointer address, int capacity, int array_offset, Class<?> cls )
  {
    Object o;
    if ( !class_map.containsValue( cls ) )
      {
        throw new IllegalArgumentException();
      }
    boolean uselong = 8 == unsafe.addressSize();
    try
      {
        o = unsafe.allocateInstance( cls );
      }
    catch (InstantiationException e)
      {
        throw new IllegalStateException();
      }
    long ptr = getNativePointer(address);
    unsafe.putIntVolatile( o, JamArrayObjectInfo.size_offset, capacity);
    if ( uselong )
      {
        unsafe.putLongVolatile( o, JamArrayObjectInfo.data_ptr_offset, ptr);
      }
    else
      {
        unsafe.putIntVolatile( o, JamArrayObjectInfo.data_ptr_offset, (int)ptr);
      }
    return o;
  }

  static native Pointer allocate(int capacity);

  static native void free(Pointer address);

  static native byte get(Pointer address, int index);

  static native void get(Pointer address, int index, byte[] dst, int offset,
                         int length);

  static native void put(Pointer address, int index, byte value);

  static native void put(Pointer address, int index, byte[] src, int offset,
                         int length);

  static native Pointer adjustAddress(Pointer address, int offset);

  static native void shiftDown(Pointer address, int dst_offset,
                               int src_offset, int count);
}
