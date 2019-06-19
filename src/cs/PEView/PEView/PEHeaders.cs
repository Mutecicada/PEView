using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Linq;
using System.Text;

namespace PEView
{
    class PEHeaders
    {
        public PEHeaders()
        {
            Func<string, string> e_magic = delegate (string str)
            {
                string ret = string.Empty;

                if (str.Equals("4D5A")) ret = "IMAGE_DOS_SIGNATURE MZ";

                return ret;
            };
            valueDic["e_magic"] = e_magic;

            Func<string, string> Signature = delegate (string str)
            {
                string ret = string.Empty;

                if (str.Equals("17744")) ret = "IMAGE_NT_SIGNATURE PE";
                return ret;
            };
            valueDic["Signature"] = Signature;

            Func<string, string> Machine = delegate (string str)
            {
                string ret = string.Empty;
                if (str.Equals("332"))
                    ret = "IMAGE_FILE_MACHINE_I386";
                else if (str.Equals("34034"))
                    ret = "IMAGE_FILE_MACHINE_AMD64";


                return ret;
            };
            valueDic["Machine"] = Machine;

            Func<string, string> Magic = delegate (string str)
            {
                string ret = string.Empty;
                if (str.Equals("267"))
                    ret = "IMAGE_OPTIONAL_HDR32_MAGIC";
                return ret;
            };
            valueDic["Magic"] = Magic;
            
        }

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

        string makeData(object data)
        {
            string tmp = null;

            if (data is char[])
            {
                var hexstring = new string(data as char[]);
                tmp = string.Join("", hexstring.Select(c => ((int)c).ToString("X")));
            }
            else if (data is UInt16[])
            {
                tmp = string.Join("", (data as UInt16[]).Select(x => x.ToString("X")).ToArray());
            }
            else if(data is byte)
            {
                tmp = ((byte)data).ToString("X");

            }
            else
            {
                tmp = data.ToString();
            }

            return tmp;
        }
        string stoh(string str)
        {
           var hexString = string.Join("", str.Select(c => ((int)c).ToString("X")));

            return hexString;
        }

        public void addToList(Type type, object obj, List<Binder> binders)
        {
            foreach(var field in type.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public))
            {
                var data = field.GetValue(obj);
                string dics = string.Empty;
                if (valueDic.ContainsKey(field.Name))
                    dics = valueDic[field.Name](makeData(data));
                else if (field.Name.Equals("Name"))
                    dics = new string((char[])field.GetValue(obj));

                binders.Add(new Binder(offset.ToString("X4"), makeData(data), field.Name, dics));
                if (data is ushort[])
                    offset += (data as ushort[]).Length * 2;
                else if (data is char[])
                    offset += (data as char[]).Length;
                else if(data is _IMAGE_DATA_DIRECTORY[])
                    offset += (data as _IMAGE_DATA_DIRECTORY[]).Length * 8;
                else
                    offset += Marshal.SizeOf(data);

            }
        }
        public void setBinderList()
        {
            int numberofsections;
            
            addToList(typeof(_DOS_HEADER), dos_header, dos_binder);

            offset = dos_header.e_lfanew;
       
            // NT Header data add to list
            if (is32)
            {
                numberofsections = nt_header32.FileHeader.NumberOfSections;
                string dic = string.Empty;
                if (valueDic.ContainsKey("Signature"))
                    dic = valueDic["Signature"](nt_header32.Signature.ToString());
                nt_binder.Add(new Binder(offset.ToString("X4"), nt_header32.Signature.ToString(), nameof(nt_header32.Signature), dic));
                offset += 4;


                addToList(typeof(_FILE_HEADER), nt_header32.FileHeader, nt_binder);
                addToList(typeof(_OPTIONAL_HEADER32), nt_header32.OptionalHeader, nt_binder);
            }

            else
            {
                numberofsections = nt_header64.FileHeader.NumberOfSections;
                string dic = string.Empty;
                if (valueDic.ContainsKey("Signature"))
                    dic = valueDic["Signature"](nt_header32.Signature.ToString());

                nt_binder.Add(new Binder(offset.ToString("X4"), nt_header64.Signature.ToString(), nameof(nt_header64.Signature), dic));
                offset += 4;

                addToList(typeof(_FILE_HEADER), nt_header64.FileHeader, nt_binder);
                addToList(typeof(_OPTIONAL_HEADER64), nt_header64.OptionalHeader, nt_binder);
            }

            sections_binder = new List<List<Binder>>();

            for (int i = 0; i < numberofsections; i++)
            {
                sections_binder.Add(new List<Binder>());
                addToList(typeof(_SECTION_HEADER), section_headers[i], sections_binder[i]);
            }
        }

        [StructLayout(LayoutKind.Sequential, Size = 1)]
        public class _DOS_HEADER
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
        public class _FILE_HEADER
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
        public class _OPTIONAL_HEADER32
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
        public class _OPTIONAL_HEADER64
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
        public class _NT_HEADERS32
        {

            public uint Signature;

            public _FILE_HEADER FileHeader;

            public _OPTIONAL_HEADER32 OptionalHeader;

        }

        [StructLayout(LayoutKind.Sequential, Size = 1)]
        public class _NT_HEADERS64
        {
            public uint Signature;
            public _FILE_HEADER FileHeader;
            public _OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Size = 1)]
        public class _SECTION_HEADER
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

        int offset = 0;
        public bool is32;

        Dictionary<string, Func<string, string>> valueDic = new Dictionary<string, Func<string, string>>();

        public List<Binder> dos_binder = new List<Binder>();
        public List<Binder> nt_binder = new List<Binder>();
        public List<List<Binder>> sections_binder;
    }

}

