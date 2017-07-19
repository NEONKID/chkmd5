#pragma once

#include <Windows.h>
#include <tchar.h>
#include <Shlwapi.h>
#include <iostream>

#pragma comment(lib, "shlwapi")

using namespace std;

class Integrity
{
public:
	Integrity(LPCTSTR filePath);
	virtual ~Integrity(void);
	DWORD getMD5();
private:
	HANDLE hFile;
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
};