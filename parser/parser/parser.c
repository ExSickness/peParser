
#include <Windows.h>
#include <stdio.h>

#define BUF_SZ 0x100

void displayDOSHeader(PIMAGE_DOS_HEADER dosHeader);
void displayImageHeader(PIMAGE_FILE_HEADER imgHeader);
void displayOptionalHeaders(PIMAGE_OPTIONAL_HEADER buf);
void displaySectionTableHeader(PIMAGE_SECTION_HEADER sectionHeader);

void displaySizes();
void printBuffer(PCHAR buffer, DWORD bufferLen, PCHAR title);

int main(int argc, char* argv[])
{
	if (2 != argc)
	{
		fprintf(stderr, "usage: %s <target executable>\n", argv[0]);
		return -1;
	}

	displaySizes();

	fprintf(stdout, "Target executable: %s\n", argv[1]);

	BOOL ret = 0;
	LONGLONG fileSize = 0;

	// Open the target file that was passed via command line
	HANDLE target = CreateFileA(argv[1],
								GENERIC_READ | GENERIC_WRITE,
								0,
								NULL,
								OPEN_EXISTING,
								0,
								NULL);

	if (INVALID_HANDLE_VALUE == target)
	{
		fprintf(stderr, "Error opening file: %d\n", GetLastError());
		return -1;
	}

	// Get the total file size
	ret = GetFileSizeEx(target, (PLARGE_INTEGER)&fileSize);
	if (!ret)
	{
		fprintf(stderr, "Error getting filesize\n");
		return -1;
	}


	// Allocate the buffer
	LONGLONG bytesLeft = 0;
	DWORD bytesRead = 0;
	PCHAR buf = calloc(1, fileSize);
	if (NULL == buf)
	{
		fprintf(stderr, "Error allocating buffer\n");
		return -1;
	}

	ret = ReadFile(target, buf, fileSize, &bytesRead, NULL);
	if (!ret || bytesRead != fileSize)
	{
		fprintf(stderr, "Error reading in target\n");
		return -1;
	}

	printf("File size: %x\n", fileSize);
	printf("Bytes read: %x\n", bytesRead);

	printf("Press enter to continue.\n");
	fgetc(stdin);

	//printBuffer(buf, bytesRead, "Executable file");

	// Parse out the DOS header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buf;
	displayDOSHeader(dosHeader);

	// Parse out the COFF header
	PIMAGE_FILE_HEADER imageHeader = dosHeader + dosHeader->e_lfanew;
	displayImageHeader(imageHeader);

	// Parse out the optional file header
	PIMAGE_OPTIONAL_HEADER optHeader = buf + 
										sizeof(IMAGE_DOS_HEADER) + 
										sizeof(IMAGE_FILE_HEADER);
	displayOptionalHeaders(optHeader);

	// Parse out the section tables
	PIMAGE_SECTION_HEADER startOfSectionHeaders = buf + 
													sizeof(IMAGE_DOS_HEADER) + 
													sizeof(IMAGE_FILE_HEADER) + 
													sizeof(IMAGE_OPTIONAL_HEADER);
	PIMAGE_SECTION_HEADER currentSection = startOfSectionHeaders;

	displaySectionTableHeader(currentSection);

	//printf("Number of sections: %x\n", imageHeader->NumberOfSections);
	//printf("Number of sections: %x\n", htons(imageHeader->NumberOfSections));
	for (int i = 0; i < imageHeader->NumberOfSections; i++)
	{
		displaySectionTableHeader(currentSection);
		currentSection += sizeof(IMAGE_SECTION_HEADER);
	}



	free(buf);
	return 0;
}

void printBuffer(PCHAR buffer, DWORD bufferLen, PCHAR title)
{
	printf("%s buffer of len %d\n", title, bufferLen);

	for (int i = 0; i < bufferLen; i++)
	{
		if (i % 8 == 0)
		{
			printf(" ");
		}
		else if (i % 16 == 0)
		{
			printf("\n");
		}

		printf("%02x ", buffer[i]);
	}

	printf("\n");
}

void displaySizes()
{
	printf("Size of char: %x\n", sizeof(char));
	printf("Size of short: %x\n", sizeof(short));
	printf("Size of int: %x\n", sizeof(int));
	printf("Size of long: %x\n", sizeof(long));

	printf("Size of BYTE: %x\n", sizeof(BYTE));
	printf("Size of BOOL: %x\n", sizeof(BOOL));
	printf("Size of WORD: %x\n", sizeof(WORD));
	printf("Size of DWORD: %x\n", sizeof(DWORD));
	printf("Size of LONGLONG: %x\n", sizeof(LONGLONG));
}

void displaySectionTableHeader(PIMAGE_SECTION_HEADER sectionHeader)
{
	printf("\n\t--- Section Header ---\n");

	//printBuffer(sectionHeader->Name, 8, "Section name");
	printf("Name - %s\n", sectionHeader->Name);
	printf("Misc - %04x\n", sectionHeader->Misc);
	printf("VirtualAddress - %04x\n", sectionHeader->VirtualAddress);
	printf("SizeOfRawData - %04x\n", sectionHeader->SizeOfRawData);
	printf("PointerToRawData - %04x\n", sectionHeader->PointerToRawData);
	printf("PointerToRelocations - %04x\n", sectionHeader->PointerToRelocations);
	printf("PointerToLinenumbers - %04x\n", sectionHeader->PointerToLinenumbers);
	printf("NumberOfRelocations - %02x\n", sectionHeader->NumberOfRelocations);
	printf("NumberOfLinenumbers - %02x\n", sectionHeader->NumberOfLinenumbers);
	printf("Characteristics - %04x\n", sectionHeader->Characteristics);

}

void displayOptionalHeaders(PIMAGE_OPTIONAL_HEADER optHeader)
{
	printf("\n\t--- Image Optional Header ---\n");

	printf("Magic - %02x\n", optHeader->Magic);
	printf("MajorLinkerVersion - %01x\n", optHeader->MajorLinkerVersion);
	printf("MinorLinkerVersion - %01x\n", optHeader->MinorLinkerVersion);
	printf("SizeOfCode - %04x\n", optHeader->SizeOfCode);
	printf("SizeOfInitializedData - %04x\n", optHeader->SizeOfInitializedData);
	printf("SizeOfUninitializedData - %04x\n", optHeader->SizeOfUninitializedData);
	printf("AddressOfEntryPoint - %04x\n", optHeader->AddressOfEntryPoint);
	printf("BaseOfCode - %04x\n", optHeader->BaseOfCode);
	printf("ImageBase - %08x\n", optHeader->ImageBase);
	printf("SectionAlignment - %04x\n", optHeader->SectionAlignment);
	printf("FileAlignment - %04x\n", optHeader->FileAlignment);
	printf("MajorOperatingSystemVersion - %02x\n", optHeader->MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion - %02x\n", optHeader->MinorOperatingSystemVersion);
	printf("MajorImageVersion - %02x\n", optHeader->MajorImageVersion);
	printf("MajorSubsystemVersion - %02x\n", optHeader->MajorSubsystemVersion);
	printf("MinorSubsystemVersion - %02x\n", optHeader->MinorSubsystemVersion);
	printf("Win32VersionValue - %04x\n", optHeader->Win32VersionValue);
	printf("SizeOfImage - %04x\n", optHeader->SizeOfImage);
	printf("SizeOfHeaders - %04x\n", optHeader->SizeOfHeaders);
	printf("CheckSum - %04x\n", optHeader->CheckSum);
	printf("Subsystem - %02x\n", optHeader->Subsystem);
	printf("DllCharacteristics - %02x\n", optHeader->DllCharacteristics);
	printf("SizeOfStackReserve - %08x\n", optHeader->SizeOfStackReserve);
	printf("SizeOfStackCommit - %08x\n", optHeader->SizeOfStackCommit);
	printf("SizeOfHeapReserve - %08x\n", optHeader->SizeOfHeapReserve);
	printf("SizeOfHeapCommit - %08x\n", optHeader->SizeOfHeapCommit);
	printf("LoaderFlags - %02x\n", optHeader->LoaderFlags);
	printf("NumberOfRvaAndSizes - %02x\n", optHeader->NumberOfRvaAndSizes);
	printf("DataDirectory - %x\n", optHeader->DataDirectory);
}

void displayImageHeader(PIMAGE_FILE_HEADER imgHeader)
{
	printf("\n\t--- Image File Header ---\n");

	printf("Machine - %02x\n", imgHeader->Machine);
	printf("NumberOfSections - %02x\n", imgHeader->NumberOfSections);
	printf("TimeDateStamp - %04x\n", imgHeader->TimeDateStamp);
	printf("PointerToSymbolTable - %04x\n", imgHeader->PointerToSymbolTable);
	printf("NumberOfSymbols - %04x\n", imgHeader->NumberOfSymbols);
	printf("SizeOfOptionalHeader - %02x\n", imgHeader->SizeOfOptionalHeader);
	printf("Characteristics - %02x\n", imgHeader->Characteristics);
}

void displayDOSHeader(PIMAGE_DOS_HEADER dosHeader)
{
	printf("\n\t--- Image DOS Header ---\n");
	printf("e_magic - %02x\n",		dosHeader->e_magic);
	printf("e_cblp - %02x\n",		dosHeader->e_cblp);
	printf("e_cp - %02x\n",		dosHeader->e_cp);
	printf("e_crlc - %02x\n",		dosHeader->e_crlc);
	printf("e_cparhdr - %02x\n",	dosHeader->e_cparhdr);
	printf("e_minalloc - %02x\n",	dosHeader->e_minalloc);
	printf("e_maxalloc - %02x\n",	dosHeader->e_maxalloc);
	printf("e_ss - %02x\n",		dosHeader->e_ss);
	printf("e_sp - %02x\n",		dosHeader->e_sp);
	printf("e_csum - %02x\n",		dosHeader->e_csum);
	printf("e_ip - %02x\n",		dosHeader->e_ip);
	printf("e_cs - %02x\n",		dosHeader->e_cs);
	printf("e_lfarlc - %02x\n",	dosHeader->e_lfarlc);
	printf("e_ovno - %02x\n",		dosHeader->e_ovno);
	printf("e_res - %02x Additional\n",		dosHeader->e_res);
	printf("e_oemid - %02x\n",		dosHeader->e_oemid);
	printf("e_oeminfo - %02x\n",	dosHeader->e_oeminfo);
	printf("e_res2 - %02x Additional\n",		dosHeader->e_res2);
	printf("e_lfanew - %04x\n",	dosHeader->e_lfanew);
}
