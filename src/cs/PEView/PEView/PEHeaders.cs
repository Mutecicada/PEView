using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.InteropServices;


namespace PEView
{
    class PEHeaders
    {
        public PEHeaders() { }

        public object read_header(FileStream fp, Type type)
        {
            int size = Marshal.SizeOf(type);
            byte[] data = new byte[size];
            fp.Read(data, 0, size);

            IntPtr buff = Marshal.AllocHGlobal(data.Length);        // 배열의 크기만큼 비관리 메모리 영역에 메모리를 할당한다.
            Marshal.Copy(data, 0, buff, data.Length);               // 배열에 저장된 데이터를 위에서 할당한 메모리 영역에 복사한다.
            object obj = Marshal.PtrToStructure(buff, type);        // 복사된 데이터를 구조체 객체로 변환한다.
            Marshal.FreeHGlobal(buff);                              // 비관리 메모리 영역에 할당했던 메모리를 해제함

            if (Marshal.SizeOf(obj) != data.Length)                 // (((PACKET_DATA)obj).TotalBytes != data.Length) // 구조체와 원래의 데이터의 크기 비교
            {
                return null;                                        // 크기가 다르면 null 리턴
            }

            return obj;                                             // 구조체 리턴
        }


        [StructLayout(LayoutKind.Sequential, Size = 1)]
        public struct _DOS_HEADER  
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;                     // 2
            ushort e_cblp;
            ushort e_cp;
            ushort e_crlc;
            ushort e_cparhdr;
            ushort e_minalloc;
            ushort e_maxalloc;
            ushort e_ss;
            ushort e_sp;
            ushort e_csum;
            ushort e_ip;
            ushort e_cs;
            ushort e_lfarlc;
            ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            ushort[] e_res;                        // 4
            ushort e_oemid;
            ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            ushort[] e_res2;                      // 10
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential, Size = 1)]
        public struct _FILE_HEADER  
        {
            ushort Machine;
            public ushort NumberOfSections;
            uint TimeDateStamp;
            uint PointerToSymbolTable;
            uint NumberOfSymbols;
            ushort SizeOfOptionalHeader;
            ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Size = 1)]
        public struct _IMAGE_DATA_DIRECTORY  
        {
            uint VirtualAddress;
            uint Size;
        }

        [StructLayout(LayoutKind.Sequential, Size = 1)]
        public struct _OPTIONAL_HEADER32  
        {
            //
            // Standard fields.
            //
            ushort Magic;
            byte MajorLinkerVersion;
            byte MinorLinkerVersion;
            uint SizeOfCode;
            uint SizeOfInitializedData;
            uint SizeOfUninitializedData;
            uint AddressOfEntryPoint;
            uint BaseOfCode;
            uint BaseOfData;

            //
            // NT additional fields.
            //

            uint ImageBase;
            uint SectionAlignment;
            uint FileAlignment;
            ushort MajorOperatingSystemVersion;
            ushort MinorOperatingSystemVersion;
            ushort MajorImageVersion;
            ushort MinorImageVersion;
            ushort MajorSubsystemVersion;
            ushort MinorSubsystemVersion;
            uint Win32VersionValue;
            uint SizeOfImage;
            uint SizeOfHeaders;
            uint CheckSum;
            ushort Subsystem;
            ushort DllCharacteristics;
            uint SizeOfStackReserve;
            uint SizeOfStackCommit;
            uint SizeOfHeapReserve;
            uint SizeOfHeapCommit;
            uint LoaderFlags;
            uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            _IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential, Size = 1)]
        public struct _OPTIONAL_HEADER64  
        {
            ushort Magic;
            byte MajorLinkerVersion;
            byte MinorLinkerVersion;
            uint SizeOfCode;
            uint SizeOfInitializedData;
            uint SizeOfUninitializedData;
            uint AddressOfEntryPoint;
            uint BaseOfCode;
            ulong ImageBase;
            uint SectionAlignment;
            uint FileAlignment;
            ushort MajorOperatingSystemVersion;
            ushort MinorOperatingSystemVersion;
            ushort MajorImageVersion;
            ushort MinorImageVersion;
            ushort MajorSubsystemVersion;
            ushort MinorSubsystemVersion;
            uint Win32VersionValue;
            uint SizeOfImage;
            uint SizeOfHeaders;
            uint CheckSum;
            ushort Subsystem;
            ushort DllCharacteristics;
            ulong SizeOfStackReserve;
            ulong SizeOfStackCommit;
            ulong SizeOfHeapReserve;
            ulong SizeOfHeapCommit;
            uint LoaderFlags;
            uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            _IMAGE_DATA_DIRECTORY[] DataDirectory;                  // 16
        }

        [StructLayout(LayoutKind.Sequential, Size = 1)]
        public struct _NT_HEADERS32  
        {

            public uint Signature;

            public _FILE_HEADER FileHeader;

            _OPTIONAL_HEADER32 OptionalHeader;

        }

        [StructLayout(LayoutKind.Sequential, Size = 1)]
        public struct _NT_HEADERS64  
        {
            uint Signature;
            public _FILE_HEADER FileHeader;
            _OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Size = 1)]
        public struct _SECTION_HEADER  
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            uint VirtualSize;

            uint VirtualAddress;
            uint SizeOfRawData;

            uint PointerToRawData;
            uint PointerToRelocations;
            uint PointerToLinenumbers;

            ushort NumberOfRelocations;
            ushort NumberOfLinenumbers;

            uint Characteristics;

        }


        public _DOS_HEADER dos_header;
        public _NT_HEADERS32 nt_header32;
        public _NT_HEADERS64 nt_header64;
        public _SECTION_HEADER[] section_headers;
    }
}

