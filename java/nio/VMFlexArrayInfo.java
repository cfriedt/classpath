package java.nio;

import sun.misc.*;

public class VMFlexArrayInfo
{
  private static final Unsafe unsafe = Unsafe.getUnsafe();
  
  private VMFlexArrayInfo() {}

  private static interface IVMFlexArrayInfo
  {
    boolean isArrayObjectFlexible();
    int arraySizeOffset();
    int dataPointerOffset();
  }
  private static final IVMFlexArrayInfo vmFlexArrayInfo;
  static {
    if ( "JamVM".equals( System.getProperty("java.vm.name") ) ) {
      vmFlexArrayInfo = new JamVMArrayInfo();
    } else {
      vmFlexArrayInfo = new OtherVMArrayInfo(); 
    }
  }
  public static boolean isArrayObjectFlexible()
  {
    return vmFlexArrayInfo.isArrayObjectFlexible();
  }
  public static int arraySizeOffset()
  {
    if ( !vmFlexArrayInfo.isArrayObjectFlexible() ) {
      throw new UnsupportedOperationException();
    }
    return vmFlexArrayInfo.arraySizeOffset();
  }
  public static int dataPointerOffset()
  {
    if ( !vmFlexArrayInfo.isArrayObjectFlexible() ) {
      throw new UnsupportedOperationException();
    }
    return vmFlexArrayInfo.dataPointerOffset();
  }
  
  /*
   * A VMArrayInfo is required for each JVM that supports VMFlexArray 
   */
  
  private static final class JamVMArrayInfo implements IVMFlexArrayInfo {
    
    private static final boolean flexible;
    private static final int size_offset;
    private static final int data_ptr_offset;

    static {
      String jamvminfo = System.getProperty("java.vm.info");
      flexible = null == jamvminfo ? false : jamvminfo.contains( "flexarray" );
      
      final int size_idx = 2;
      size_offset = flexible ? unsafe.addressSize() * size_idx : -1;
      
      final int data_ptr_idx = 3;
      data_ptr_offset = flexible ? unsafe.addressSize() * data_ptr_idx : -1;
    }
    
    public boolean isArrayObjectFlexible()
    {
      return flexible;
    }
    public int arraySizeOffset()
    {
      return size_offset;
    }
    public int dataPointerOffset()
    {
      return data_ptr_offset;
    }
  };
  
  private static final class OtherVMArrayInfo implements IVMFlexArrayInfo {

    public boolean isArrayObjectFlexible()
    {
      return false;
    }

    public int arraySizeOffset()
    {
      return -1;
    }

    public int dataPointerOffset()
    {
      return -1;
    }
    
  }
}
