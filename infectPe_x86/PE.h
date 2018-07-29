#pragma once
#include <Windows.h>
#include <stdio.h>
#pragma warning(disable : 4996)


typedef struct
{
	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNtHeaders;
	PIMAGE_SECTION_HEADER	pSectionHeader[100];

	CHAR	   				*dwDosStup;
	DWORD					dwSectionCount;
	DWORD					dwImage;
	DWORD					dwImageSizeOnDisk;
} PE_Info;

void writeToFile(PE_Info, PE_Info, int, char*);
void init(FILE *, PE_Info *, CHAR *);
void addSection(PE_Info, int, char *);
