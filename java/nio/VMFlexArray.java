package java.nio;

import gnu.classpath.*;

import java.lang.reflect.*;
import java.util.*;

import sun.misc.*;

class VMFlexArray
{
  private VMFlexArray() {}

  private static boolean enable;
  private static final Unsafe unsafe;
  private static final Field ptrdata;

  static
    {
      enable = Boolean.parseBoolean( System.getProperty("gnu.classpath.flexarray.enable") );
      unsafe = Unsafe.getUnsafe();
      if ( enable )
        {
          ptrdata = initPtrData();
          if ( null != ptrdata )
            {
              ptrdata.setAccessible(true);
            }
        }
      else
        {
          ptrdata = null;
        }
    }

  private static Field initPtrData()
  {

    Field r = null;
    Exception e2 = null;

    try
      {
        switch (unsafe.addressSize())
          {
          case 4:
            r = Pointer32.class.getDeclaredField("data");
            break;
          case 8:
            r = Pointer64.class.getDeclaredField("data");
            break;
          default:
            throw new IllegalStateException();
          }
      }
    catch (Exception e)
      {
        e2 = e;
      }
    if (null != e2)
      {
        IllegalStateException ex = new IllegalStateException();
        ex.setStackTrace(e2.getStackTrace());
        throw ex;
      }
    r.setAccessible( true );
    return r;
  }
  
  private static long getNativePointer( Pointer ptr, int address_size ) {
    long r = -1;
    Exception e2 = null;
    
    try {
      switch( unsafe.addressSize() ) {
        case 4:
          r = ptrdata.getInt( ptr );
          break;
        case 8:
          r = ptrdata.getLong( ptr );
          break;
      }
    } catch (IllegalAccessException e ) {
      e2 = e;
    }
    if ( null != e2 ) {
      IllegalStateException ex = new IllegalStateException();
      ex.setStackTrace( e2.getStackTrace() );
      throw ex;
    }
    return r;
  }
  
  private static final HashSet<Class<?>> array_classes;
  static
    {
      array_classes = new HashSet<Class<?>>();
      array_classes.add( boolean[].class );
      array_classes.add( byte[].class );
      array_classes.add( char[].class );
      array_classes.add( short[].class );
      array_classes.add( int[].class );
      array_classes.add( long[].class );
      array_classes.add( float[].class );
      array_classes.add( double[].class );
    }

  static Object pointerToArray(Pointer address, int capacity, int array_offset, Class<?> cls )
  { 
    Object o = null;
    
    if ( !enable )
      {
        return o;
      }

    if ( !VMFlexArrayInfo.isArrayObjectFlexible() )
      {
        //throw new UnsupportedOperationException();
        return o;
      }
    
    // only deal array types defined in array_classes (i.e. primitives)
    if ( !array_classes.contains( cls ) )
      {
        throw new IllegalArgumentException();
      }
    
    Exception e1 = null;
    try
      {
        o = unsafe.allocateInstance( cls );
      }
    catch (InstantiationException e)
      {
        e1 = e;
      }
    if ( null != e1 ) {
      // catch InstantiationException and throw an exception that does not need to be declared
      UnsupportedOperationException e2 = new UnsupportedOperationException(); 
      e2.setStackTrace( e1.getStackTrace() );
      throw e2;
    }
    
    switch( unsafe.addressSize() )
      {
        case 4:
          int ptr32 = (int) getNativePointer(address, 4);
          unsafe.putIntVolatile( o, VMFlexArrayInfo.dataPointerOffset(), ptr32);
          break;
        case 8:
          long ptr64 = getNativePointer(address, 8);
          unsafe.putLongVolatile( o, VMFlexArrayInfo.dataPointerOffset(), ptr64);
          break;
        default:
          throw new IllegalStateException( "unrecognized result from sun.misc.Unsafe.addressSize()" );
      }
    unsafe.putIntVolatile( o, VMFlexArrayInfo.arraySizeOffset(), capacity );
    return o;
  }
}
