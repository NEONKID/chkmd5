#include "chkIntegrity.h"

#define BUFSIZE	1024
#define MD5LEN	16

Integrity::Integrity(LPCTSTR filePath)
{
	hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	hProv = 0;
	hHash = 0;
}

Integrity::~Integrity(void)
{
	CloseHandle(hFile);
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
}

DWORD Integrity::getMD5()
{
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	BYTE rgbFile[BUFSIZE];
	BYTE rgbHash[MD5LEN];
	DWORD cbRead = 0;
	DWORD cbHash = 0;
	TCHAR rgbDigits[] = _T("0123456789ABCDEF");

	if (hFile == INVALID_HANDLE_VALUE)
	{
		dwStatus = GetLastError();
		wcout << _T("ERR CODE: ") << dwStatus << endl;
		wcout << _T("INVALID HANDLE !") << endl;
		return dwStatus;
	}

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		DWORD dwStatus = GetLastError();
		wcout << _T("ERR CODE: ") << dwStatus << endl;
		wcout << _T("Invalid CryptAcquireContext !") << endl;
		return dwStatus;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		wcout << _T("ERR CODE: ") << dwStatus << endl;
		wcout << _T("There was an error creating the hash !") << endl;
		return dwStatus;
	}

	while (bResult = ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL))
	{
		if (cbRead == 0)
		{
			break;
		}
		else if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			dwStatus = GetLastError();
			wcout << _T("ERR CODE: ") << dwStatus << endl;
			wcout << _T("File is reading ERR !") << endl;
			return dwStatus;
		}
	}

	if (!bResult)
	{
		dwStatus = GetLastError();
		wcout << _T("ERR CODE: ") << dwStatus << endl;
		wcout << _T("Unknown ERR !") << endl;
		return dwStatus;
	}

	cbHash = MD5LEN;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		wcout << _T("MD5 hash of file: ");
		for (DWORD i = 0; i < cbHash; i++)
		{
			wcout << rgbDigits[rgbHash[i] >> 4] << rgbDigits[rgbHash[i] & 0xf];
		}
		wcout << endl;
		return 0x00;
	}
	else
	{
		dwStatus = GetLastError();
		wcout << _T("ERR CODE: ") << dwStatus << endl;
		wcout << _T("CryptGetHashParam failed: ") << dwStatus << endl;
		return dwStatus;
	}
}