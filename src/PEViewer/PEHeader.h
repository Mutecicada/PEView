#pragma once

typedef struct _DOS_HEADER {
	char   e_magic[2];
	WORD   e_cblp;
	WORD   e_cp;
	WORD   e_crlc;
	WORD   e_cparhdr;
	WORD   e_minalloc;
	WORD   e_maxalloc;
	WORD   e_ss;
	WORD   e_sp;
	WORD   e_csum;
	WORD   e_ip;
	WORD   e_cs;
	WORD   e_lfarlc;
	WORD   e_ovno;
	WORD   e_res[4];
	WORD   e_oemid;
	WORD   e_oeminfo;
	WORD   e_res2[10];
	LONG   e_lfanew;
} DOS_HEADER, *DOS_HEADER_PTR;


typedef struct _FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} FILE_HEADER, *FILE_HEADER_PTR;

typedef struct _OPTIONAL_HEADER32 {
	//
	// Standard fields.
	//

	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;

	//
	// NT additional fields.
	//

	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} OPTIONAL_HEADER32, *OPTIONAL_HEADER32_PTR;


typedef struct _NT_HEADERS32 {

	DWORD Signature;

	_FILE_HEADER FileHeader;

	OPTIONAL_HEADER32 OptionalHeader;

} NT_HEADERS32, *NT_HEADERS32_PTR;

typedef struct _SECTION_HEADER {
	BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	
	union {
		DWORD PhysicalAddress;		//	직접 접근 불가능
		DWORD VirtualSize; 
	} Misc; 

	DWORD VirtualAddress;
	DWORD SizeOfRawData;

	DWORD PointerToRawData; 
	DWORD PointerToRelocations; 
	DWORD PointerToLinenumbers; 
	
	WORD NumberOfRelocations; 
	WORD NumberOfLinenumbers; 
	
	DWORD Characteristics; 

} SECTION_HEADER, *SECTION_HEADER_PTR;
