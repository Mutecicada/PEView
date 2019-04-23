#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include "PEHeader.h"

#define MAX_PATH 260

//typedef unsigned short WORD;


DOS_HEADER dos_header;
unsigned char *dos_stub;
NT_HEADERS32 nt_header32;
NT_HEADERS64 nt_header64;
SECTION_HEADER *section_header;
bool isOpen;
bool is32;

void file_open(char *path);

void read_dos(FILE *fp);
void dos_header_info();

void read_dos_stub(FILE *fp);
void dos_stub_info();

void read_nt(FILE *fp);
void nt_header_info();

void read_section(FILE *fp);
void section_header_info();

int main()
{
	isOpen = false;
	int menu;
	char path[MAX_PATH];

	while (1)
	{
		printf("0. Exit\n");
		printf("1. File Open\n");
		printf("2. DOS_HEADER\n");
		printf("3. DOS_STUB\n");
		printf("4. NT_HEADER\n");
		printf("5. SECTION_HEADERS\n");
		printf("Select Menu : ");
		scanf("%d", &menu);

		switch (menu)
		{
		case 0:;
			free(section_header);
			return -1;
			break;

		case 1:
			printf("\nInput FIle Path : ");
			scanf("%s[^\n]", path);
			file_open(path);
			break;

		case 2:
			dos_header_info();
			break;

		case 3:
			dos_stub_info();
			break;

		case 4:
			nt_header_info();
			break;

		case 5:
			section_header_info();
			break;
		}
	}

	return 0;
}

void file_open(char *path)
{
	FILE *fp;

	fp = fopen(path, "rb");
	if (fp == NULL)
	{
		printf("\n\nFile Open Error\n\n");
		isOpen = false;
	}
	else
	{
		printf("\n\nFile Open Success\n\n");
	}

	read_dos(fp);
	read_dos_stub(fp);
	read_nt(fp);
	read_section(fp);

	fclose(fp);

	isOpen = true;
}

void read_dos(FILE *fp)
{
	unsigned buffer[255];

	fseek(fp, 0, SEEK_SET);
	fread(buffer, sizeof(DOS_HEADER), 1, fp);
	dos_header = *(DOS_HEADER*)buffer;
}

void dos_header_info()
{
	if (!isOpen)
	{
		printf("File Open First!\n\n");
		return;
	}
	printf("\nsignature : %c%c\n", dos_header.e_magic[0], dos_header.e_magic[1]);
	printf("lastsize : %04X\n", dos_header.e_cblp);
	printf("nblocks : %04X\n", dos_header.e_cp);
	printf("nreloc : %04X\n", dos_header.e_crlc);
	printf("hdrsize : %04X\n", dos_header.e_cparhdr);
	printf("minalloc : %04X\n", dos_header.e_minalloc);
	printf("maxalloc : %04X\n", dos_header.e_maxalloc);
	printf("ss : %04X\n", dos_header.e_ss);
	printf("sp : %04X\n", dos_header.e_sp);
	printf("checksum : %04X\n", dos_header.e_csum);
	printf("ip : %04X\n", dos_header.e_ip);
	printf("cs : %04X\n", dos_header.e_cs);
	printf("relocpos : %04X\n", dos_header.e_lfarlc);
	printf("noverlay : %04X\n", dos_header.e_ovno);

	for (int i = 0; i < 4; i++)
	{
		printf("Reserved : %04X\n", dos_header.e_res[i]);
	}
	printf("OEM Identifier : %04X\n", dos_header.e_oemid);
	printf("OEN Information : %04X\n", dos_header.e_oeminfo);

	for (int i = 0; i < 10; i++)
		printf("Reserved : %04X\n", dos_header.e_res2[i]);

	printf("offset to NT header : %X\n\n", dos_header.e_lfanew);
}

void read_dos_stub(FILE *fp)
{
	if (fp == NULL)
	{
		printf("\n\nFile Open First\n\n");
		return;
	}
	fseek(fp, sizeof(DOS_HEADER), SEEK_SET);

	int size = dos_header.e_lfanew - sizeof(DOS_HEADER);

	dos_stub = (unsigned char*)malloc(sizeof(char) * size);
	size_t ret = fread(dos_stub, sizeof(char), size, fp);

}
void dos_stub_info()
{
	if (!isOpen)
	{
		printf("File Open First!\n\n");
		return;
	}
	printf("offset(h)  ");
	for (int i = 0; i < 16; i++)	printf("%02X ", i);
	printf("\n==========================================================\n");

	int size = (dos_header.e_lfanew - sizeof(DOS_HEADER)) / 16 + 1;
	for (int i = 0; i < size; i++)
	{
		printf("%08X   ", (16 * i));
		for (int j = 0; j < 16; j++)
		{
			printf("%02X ", dos_stub[16 * i + j]);
		}
		printf("  ");
		for (int l = 0; l < 16; l++)
		{
			if (dos_stub[16 * i + l] <= 127 && dos_stub[16 * i + l] >= 15)
				printf("%c", dos_stub[16 * i + l]);

			else
				printf(".");
		}
		printf("\n");
	}
	printf("\n");
}

void read_nt(FILE *fp)
{
	unsigned char buffer[270];

	fseek(fp, dos_header.e_lfanew + 4, SEEK_SET);
	
	WORD machine = NULL;
	fread(&machine, sizeof(WORD), 1, fp);
	fseek(fp, dos_header.e_lfanew, SEEK_SET);

	if ((int)machine == IMAGE_FILE_MACHINE_I386)				// 32 bit
	{
		fread(buffer, sizeof(NT_HEADERS32), 1, fp);
		nt_header32 = *(NT_HEADERS32*)buffer;
		is32 = true;
	}
	else							// 64 bit
	{
		fread(buffer, sizeof(NT_HEADERS64), 1, fp);
		nt_header64 = *(NT_HEADERS64*)buffer;
		is32 = false;
	}

}

void nt_header_info()
{
	if (!isOpen)
	{
		printf("File Open First!\n\n");
		return;
	}

	if (is32)
	{
		printf("\nSignature : %08X\n", nt_header32.Signature);

		printf("\n------------FILE HEADER------------\n");
		printf("Machine : %04X\n", nt_header32.FileHeader.Machine);
		printf("Number of Sections : %04X\n", nt_header32.FileHeader.NumberOfSections);
		printf("TIme Date Stamp : %08X\n", nt_header32.FileHeader.TimeDateStamp);
		printf("Pointer to Symbol Table : %08X\n", nt_header32.FileHeader.PointerToSymbolTable);
		printf("Number of Symbols : %08X\n", nt_header32.FileHeader.NumberOfSymbols);
		printf("Size Of Optional Header : %04X\n", nt_header32.FileHeader.SizeOfOptionalHeader);
		printf("Characteristics : %04X\n\n", nt_header32.FileHeader.Characteristics);

		printf("\n------------OPTIONAL HEADER------------\n");
		printf("Magic : %04X\n", nt_header32.OptionalHeader.Magic);
		printf("Major Linker Version : %02X\n", nt_header32.OptionalHeader.MajorLinkerVersion);
		printf("Minor Linker Version : %02X\n", nt_header32.OptionalHeader.MinorLinkerVersion);
		printf("Size of Code : %08X\n", nt_header32.OptionalHeader.SizeOfCode);
		printf("Size Of Initialized Data %08X\n", nt_header32.OptionalHeader.SizeOfInitializedData);
		printf("Size Of Uninitialized Data : %08X\n", nt_header32.OptionalHeader.SizeOfUninitializedData);
		printf("Address of Entry Point : %08X\n", nt_header32.OptionalHeader.AddressOfEntryPoint);
		printf("Base of Code : %08X\n", nt_header32.OptionalHeader.BaseOfCode);
		printf("Base of Data : %08X\n", nt_header32.OptionalHeader.BaseOfData);
		printf("Image Baase : : %08X\n", nt_header32.OptionalHeader.ImageBase);
		printf("Section Alignment : %08X\n", nt_header32.OptionalHeader.SectionAlignment);
		printf("File Alignment : %08X\n", nt_header32.OptionalHeader.FileAlignment);
		printf("Majog O/S Version : %04X\n", nt_header32.OptionalHeader.MajorOperatingSystemVersion);
		printf("Minor O/S Version : %04X\n", nt_header32.OptionalHeader.MinorOperatingSystemVersion);
		printf("Major Image Versoin : %04X\n", nt_header32.OptionalHeader.MajorImageVersion);
		printf("Minor Image Version : %04X\n", nt_header32.OptionalHeader.MinorImageVersion);
		printf("Major Subsystem Version : %04X\n", nt_header32.OptionalHeader.MajorSubsystemVersion);;
		printf("Minor Subsystem Version : %04X\n", nt_header32.OptionalHeader.MinorImageVersion);
		printf("Win32 Version Value : %08X\n", nt_header32.OptionalHeader.Win32VersionValue);
		printf("Size of Image : %08X\n", nt_header32.OptionalHeader.SizeOfImage);
		printf("Size of Headers : %08X\n", nt_header32.OptionalHeader.SizeOfHeaders);
		printf("Checksum : %08X\n", nt_header32.OptionalHeader.CheckSum);
		printf("Subsystem : %04X\n", nt_header32.OptionalHeader.Subsystem);
		printf("DLL Characteristics : %04X\n", nt_header32.OptionalHeader.DllCharacteristics);
		printf("Size of Stack Reserve : %08X\n", nt_header32.OptionalHeader.SizeOfStackReserve);
		printf("Size of Stack Commit : %08X\n", nt_header32.OptionalHeader.SizeOfStackCommit);
		printf("Size of Heap Reserve : %08X\n", nt_header32.OptionalHeader.SizeOfHeapReserve);
		printf("Size of Heap Commit : %08X\n", nt_header32.OptionalHeader.SizeOfHeapCommit);
		printf("Loader Flags : %08X\n", nt_header32.OptionalHeader.LoaderFlags);
		printf("Number of Data Directories : %08X\n", nt_header32.OptionalHeader.NumberOfRvaAndSizes);

		for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		{
			printf("RVA  : %08X\n", nt_header32.OptionalHeader.DataDirectory[i].VirtualAddress);
			printf("Size : %08X\n", nt_header32.OptionalHeader.DataDirectory[i].Size);
		}
	}
	else
	{
		printf("\nSignature : %08X\n", nt_header64.Signature);

		printf("\n------------FILE HEADER------------\n");
		printf("Machine : %04X\n", nt_header64.FileHeader.Machine);
		printf("Number of Sections : %04X\n", nt_header64.FileHeader.NumberOfSections);
		printf("TIme Date Stamp : %08X\n", nt_header64.FileHeader.TimeDateStamp);
		printf("Pointer to Symbol Table : %08X\n", nt_header64.FileHeader.PointerToSymbolTable);
		printf("Number of Symbols : %08X\n", nt_header64.FileHeader.NumberOfSymbols);
		printf("Size Of Optional Header : %04X\n", nt_header64.FileHeader.SizeOfOptionalHeader);
		printf("Characteristics : %04X\n\n", nt_header64.FileHeader.Characteristics);

		printf("\n------------OPTIONAL HEADER------------\n");
		printf("Magic : %04X\n", nt_header64.OptionalHeader.Magic);
		printf("Major Linker Version : %02X\n", nt_header64.OptionalHeader.MajorLinkerVersion);
		printf("Minor Linker Version : %02X\n", nt_header64.OptionalHeader.MinorLinkerVersion);
		printf("Size of Code : %08X\n", nt_header64.OptionalHeader.SizeOfCode);
		printf("Size Of Initialized Data %08X\n", nt_header64.OptionalHeader.SizeOfInitializedData);
		printf("Size Of Uninitialized Data : %08X\n", nt_header64.OptionalHeader.SizeOfUninitializedData);
		printf("Address of Entry Point : %08X\n", nt_header64.OptionalHeader.AddressOfEntryPoint);
		printf("Base of Code : %08X\n", nt_header64.OptionalHeader.BaseOfCode);
		printf("Image Baase : : %08X\n", nt_header64.OptionalHeader.ImageBase);
		printf("Section Alignment : %08X\n", nt_header64.OptionalHeader.SectionAlignment);
		printf("File Alignment : %08X\n", nt_header64.OptionalHeader.FileAlignment);
		printf("Majog O/S Version : %04X\n", nt_header64.OptionalHeader.MajorOperatingSystemVersion);
		printf("Minor O/S Version : %04X\n", nt_header64.OptionalHeader.MinorOperatingSystemVersion);
		printf("Major Image Versoin : %04X\n", nt_header64.OptionalHeader.MajorImageVersion);
		printf("Minor Image Version : %04X\n", nt_header64.OptionalHeader.MinorImageVersion);
		printf("Major Subsystem Version : %04X\n", nt_header64.OptionalHeader.MajorSubsystemVersion);;
		printf("Minor Subsystem Version : %04X\n", nt_header64.OptionalHeader.MinorImageVersion);
		printf("Win32 Version Value : %08X\n", nt_header64.OptionalHeader.Win32VersionValue);
		printf("Size of Image : %08X\n", nt_header64.OptionalHeader.SizeOfImage);
		printf("Size of Headers : %08X\n", nt_header64.OptionalHeader.SizeOfHeaders);
		printf("Checksum : %08X\n", nt_header64.OptionalHeader.CheckSum);
		printf("Subsystem : %04X\n", nt_header64.OptionalHeader.Subsystem);
		printf("DLL Characteristics : %04X\n", nt_header64.OptionalHeader.DllCharacteristics);
		printf("Size of Stack Reserve : %08X\n", nt_header64.OptionalHeader.SizeOfStackReserve);
		printf("Size of Stack Commit : %08X\n", nt_header64.OptionalHeader.SizeOfStackCommit);
		printf("Size of Heap Reserve : %08X\n", nt_header64.OptionalHeader.SizeOfHeapReserve);
		printf("Size of Heap Commit : %08X\n", nt_header64.OptionalHeader.SizeOfHeapCommit);
		printf("Loader Flags : %08X\n", nt_header64.OptionalHeader.LoaderFlags);
		printf("Number of Data Directories : %08X\n", nt_header64.OptionalHeader.NumberOfRvaAndSizes);

		for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		{
			printf("RVA  : %08X\n", nt_header64.OptionalHeader.DataDirectory[i].VirtualAddress);
			printf("Size : %08X\n", nt_header64.OptionalHeader.DataDirectory[i].Size);
		}
	}
	printf("\n\n");
}


void read_section(FILE *fp)
{
	int NumberOfSections;

	if(is32)
		NumberOfSections = nt_header32.FileHeader.NumberOfSections;
	else
		NumberOfSections = nt_header64.FileHeader.NumberOfSections;
	
	unsigned char buffer[400];
	section_header = (SECTION_HEADER*)malloc(sizeof(SECTION_HEADER) * NumberOfSections);

	for (int i = 0; i < NumberOfSections; i++)
	{
		size_t ret = fread(buffer, sizeof(char), sizeof(SECTION_HEADER), fp);
		section_header[i] = *(SECTION_HEADER*)buffer;
	}
}

void section_header_info()
{
	if (!isOpen)
	{
		printf("File Open First!\n\n");
		return;
	}
	int NumberOfSection;
	if (is32)
		NumberOfSection = nt_header32.FileHeader.NumberOfSections;
	else
		NumberOfSection = nt_header64.FileHeader.NumberOfSections;

	for (int i = 0; i < NumberOfSection; i++)
	{
		printf("\n\n---------------%s---------------\n", section_header[i].Name);
		printf("Virtual SIze          : %08X\n", section_header[i].Misc.VirtualSize);
		printf("Virtual Addresss(RVA) : %08X\n", section_header[i].VirtualAddress);
		printf("Size of Raw Data      : %08X\n", section_header[i].SizeOfRawData);
		printf("Pointer to Raw Data   : %08X\n", section_header[i].PointerToRawData);
		printf("Characteristics       : %08X\n", section_header[i].Characteristics);
		system("pause");
	}
}
