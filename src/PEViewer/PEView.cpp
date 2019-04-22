#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include "PEHeader.h"

#define MAX_PATH 260

//typedef unsigned short WORD;


DOS_HEADER dos_header;
NT_HEADERS32 nt_header;
SECTION_HEADER *section_header;

FILE *file_open();

void read_dos(FILE *fp);
void dos_header_info();

void dos_stub_info(FILE * fp);

void read_nt(FILE *fp);
void nt_header_info();

void read_section(FILE *fp);
void section_header_info();

int main()
{
	FILE *fp = NULL;

	int menu;
	while (1)
	{
		printf("0. 종료\n");
		printf("1. 파일 열기\n");
		printf("2. DOS_HEADER\n");
		printf("3. DOS_STUB\n");
		printf("4. NT_HEADER\n");
		printf("5. SECTION_HEADERS\n");
		printf("메뉴 선택 : ");
		scanf("%d", &menu);

		switch (menu)
		{
		case 0:
			if (fp != NULL)	fclose(fp);
			//free(section_header);
			return -1;
			break;

		case 1:
			fp = file_open();
			break;

		case 2:
			dos_header_info();
			break;

		case 3:
			dos_stub_info(fp);
			break;

		case 4:
			nt_header_info();
			break;

		case 5:
			section_header_info();
			break;
		}
	}

	fclose(fp);

	return 0;
}

FILE *file_open()
{
	FILE *fp;
	char file_path[MAX_PATH];


	printf("\nInput FIle Path : ");
	scanf("%s[^\n]", file_path);

	fp = fopen(file_path, "rb");
	if (fp == NULL)
	{
		printf("\n\nFile Open Error\n\n");
		return fp;
	}
	else
	{
		printf("\n\nFile Open Success\n\n");
	}

	read_dos(fp);
	read_nt(fp);
	read_section(fp);

	return fp;
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

void dos_stub_info(FILE *fp)
{
	if (fp == NULL)
	{
		printf("\n\nFile Open First\n\n");
		return;
	}

	
	fseek(fp, sizeof(DOS_HEADER), SEEK_SET);
	unsigned char buffer[1024];
	size_t ret = fread(buffer, sizeof(char), dos_header.e_lfanew - sizeof(DOS_HEADER), fp);


	printf("offset(h)  ");
	for (int i = 0; i < 16; i++)	printf("%02X ", i);
	printf("\n==========================================================\n");


	for (int i = 0; i < ret / 16 + 1; i++)
	{
		printf("%08X   ", (16 * i));
		for (int j = 0; j < 16; j++)
		{
			printf("%02X ", buffer[16 * i + j]);
		}
		printf("  ");
		for (int l = 0; l < 16; l++)
		{
			if (buffer[16 * i + l] <= 127 && buffer[16 * i + l] >= 15)
				printf("%c", buffer[16 * i + l]);

			else
				printf(".");
		}
		printf("\n");
	}
	printf("\n");
}

void read_nt(FILE *fp)
{
	unsigned char buffer[255];

	fseek(fp, dos_header.e_lfanew, SEEK_SET);
	fread(buffer, sizeof(NT_HEADERS32), 1, fp);

	nt_header = *(NT_HEADERS32*)buffer;
}

void nt_header_info()
{
	printf("\nSignature : %08X\n", nt_header.Signature);

	printf("\n------------FILE HEADER------------\n");
	printf("Machine : %04X\n", nt_header.FileHeader.Machine);
	printf("Number of Sections : %04X\n", nt_header.FileHeader.NumberOfSections);
	printf("TIme Date Stamp : %08X\n", nt_header.FileHeader.TimeDateStamp);
	printf("Pointer to Symbol Table : %08X\n", nt_header.FileHeader.PointerToSymbolTable);
	printf("Number of Symbols : %08X\n", nt_header.FileHeader.NumberOfSymbols);
	printf("Size Of Optional Header : %04X\n", nt_header.FileHeader.SizeOfOptionalHeader);
	printf("Characteristics : %04X\n\n", nt_header.FileHeader.Characteristics);

	printf("\n------------OPTIONAL HEADER------------\n");
	printf("Magic : %04X\n", nt_header.OptionalHeader.Magic);
	printf("Major Linker Version : %02X\n", nt_header.OptionalHeader.MajorLinkerVersion);
	printf("Minor Linker Version : %02X\n", nt_header.OptionalHeader.MinorLinkerVersion);
	printf("Size of Code : %08X\n", nt_header.OptionalHeader.SizeOfCode);
	printf("Size Of Initialized Data %08X\n", nt_header.OptionalHeader.SizeOfInitializedData);
	printf("Size Of Uninitialized Data : %08X\n", nt_header.OptionalHeader.SizeOfUninitializedData);
	printf("Address of Entry Point : %08X\n", nt_header.OptionalHeader.AddressOfEntryPoint);
	printf("Base of Code : %08X\n", nt_header.OptionalHeader.BaseOfCode);
	printf("Base of Data : %08X\n", nt_header.OptionalHeader.BaseOfData);
	printf("Image Baase : : %08X\n", nt_header.OptionalHeader.ImageBase);
	printf("Section Alignment : %08X\n", nt_header.OptionalHeader.SectionAlignment);
	printf("File Alignment : %08X\n", nt_header.OptionalHeader.FileAlignment);
	printf("Majog O/S Version : %04X\n", nt_header.OptionalHeader.MajorOperatingSystemVersion);
	printf("Minor O/S Version : %04X\n", nt_header.OptionalHeader.MinorOperatingSystemVersion);
	printf("Major Image Versoin : %04X\n", nt_header.OptionalHeader.MajorImageVersion);
	printf("Minor Image Version : %04X\n", nt_header.OptionalHeader.MinorImageVersion);
	printf("Major Subsystem Version : %04X\n", nt_header.OptionalHeader.MajorSubsystemVersion);;
	printf("Minor Subsystem Version : %04X\n", nt_header.OptionalHeader.MinorImageVersion);
	printf("Win32 Version Value : %08X\n", nt_header.OptionalHeader.Win32VersionValue);
	printf("Size of Image : %08X\n", nt_header.OptionalHeader.SizeOfImage);
	printf("Size of Headers : %08X\n", nt_header.OptionalHeader.SizeOfHeaders);
	printf("Checksum : %08X\n", nt_header.OptionalHeader.CheckSum);
	printf("Subsystem : %04X\n", nt_header.OptionalHeader.Subsystem);
	printf("DLL Characteristics : %04X\n", nt_header.OptionalHeader.DllCharacteristics);
	printf("Size of Stack Reserve : %08X\n", nt_header.OptionalHeader.SizeOfStackReserve);
	printf("Size of Stack Commit : %08X\n", nt_header.OptionalHeader.SizeOfStackCommit);
	printf("Size of Heap Reserve : %08X\n", nt_header.OptionalHeader.SizeOfHeapReserve);
	printf("Size of Heap Commit : %08X\n", nt_header.OptionalHeader.SizeOfHeapCommit);
	printf("Loader Flags : %08X\n", nt_header.OptionalHeader.LoaderFlags);
	printf("Number of Data Directories : %08X\n", nt_header.OptionalHeader.NumberOfRvaAndSizes);

	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		printf("RVA  : %08X\n", nt_header.OptionalHeader.DataDirectory[i].VirtualAddress);
		printf("Size : %08X\n", nt_header.OptionalHeader.DataDirectory[i].Size);
	}
	printf("\n\n");
}


void read_section(FILE *fp)
{
	int NumberOfSections = nt_header.FileHeader.NumberOfSections;

	unsigned char buffer[400];
	section_header = (SECTION_HEADER*)malloc(sizeof(SECTION_HEADER) * NumberOfSections);


	//fread(buffer, sizeof(char), 400, fp);

	for (int i = 0; i < NumberOfSections; i++)
	{
		//printf("%d\n", i);
		size_t ret = fread(buffer, sizeof(char), sizeof(SECTION_HEADER), fp);
		section_header[i] = *(SECTION_HEADER*)buffer;
	//	fseek(fp, cur + 40, SEEK_SET);
	}
}

void section_header_info()
{
	for (int i = 0; i < nt_header.FileHeader.NumberOfSections; i++)
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