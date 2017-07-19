#include "chkIntegrity.h"

int _tmain(int argc, TCHAR **argv)
{
	DWORD dwStatus = 0;
	if (argv[1] == NULL)
	{
		dwStatus = GetLastError();
		wcout << _T("Program usage: Command [File Path]") << endl;
		return dwStatus;
	}
	LPCTSTR filePath = argv[1];
	wcout << "File name: " << PathFindFileName(filePath) << endl;

	Integrity integrity(filePath);
	dwStatus = integrity.getMD5();

	return dwStatus;
}