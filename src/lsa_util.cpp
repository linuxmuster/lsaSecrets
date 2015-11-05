#include <stdio.h>

#include "lsa_util.h"

BOOL InitLsaString(
		PLSA_UNICODE_STRING pLsaString,
		LPCWSTR pwszString
)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
		return FALSE;

	if (NULL != pwszString) 
	{
		dwLen = wcslen(pwszString);
		if (dwLen > 0x7ffe)   // String is too large
			return FALSE;
	}

	// Store the string.
	pLsaString->Buffer = (WCHAR *)pwszString;
	pLsaString->Length =  (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength= (USHORT)(dwLen+1) * sizeof(WCHAR);

	return TRUE;
}

BOOL CreatePrivateDataObject(
		LSA_HANDLE PolicyHandle,	// must be opened with POLICY_CREATE_SECRET
		CHAR *szName,
		CHAR *szPrvData)
{
	NTSTATUS ntsResult;
	LSA_UNICODE_STRING lucKeyName;
	LSA_UNICODE_STRING lucPrivateData;

	// Construct key name
	// The L$ prefix specifies a local private data object
	wchar_t wszKeyName[100] = {0};
        // thomas@linuxmuster.net: let us access $MACHINE.ACC
	// wcsncat_s(wszKeyName, 100, L"L$", 2);

	wchar_t wcstringName[50];
	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, wcstringName, strlen(szName)+1, szName, _TRUNCATE);
	wcsncat_s(wszKeyName, 100, wcstringName, strlen(szName)+1);	
	wprintf(L"Key Name: %s\n", wszKeyName);
	// Initializing PLSA_UNICODE_STRING structures
	if (!InitLsaString(&lucKeyName, wszKeyName))
	{
		wprintf(L"Failed InitLsaString\n");
		return FALSE;
	}
	
	// Construct key private data
	wchar_t wszPrivateData[100] = {0};

	wchar_t wcstringData[50];
	convertedChars = 0;
	mbstowcs_s(&convertedChars, wcstringData, strlen(szPrvData)+1, szPrvData, _TRUNCATE);
	wcsncat_s(wszPrivateData, 100, wcstringData, strlen(szPrvData)+1);	
	wprintf(L"Key private data: %s\n", wszPrivateData);

	if (!InitLsaString(&lucPrivateData, wszPrivateData))
	{
		wprintf(L"Failed InitLsaString\n");
		return FALSE;
	}
			
	// Store the private data.
	ntsResult = LsaStorePrivateData(
			PolicyHandle,   // handle to a Policy object
			&lucKeyName,    // key to identify the data
			&lucPrivateData // the private data
	);
	if (ntsResult != ERROR_SUCCESS)
	{
		wprintf(L"LsaStorePrivateData failed:\n");
		GetLSAErrorStatus(ntsResult);				
		return FALSE;
	}
	return TRUE;
}

BOOL ReadPrivateDataObject(
		LSA_HANDLE PolicyHandle,
		CHAR *szName)
{
	NTSTATUS ntsResult;
	LSA_UNICODE_STRING lucKeyName;
	LSA_UNICODE_STRING *lucPrivateData = NULL;

	// Construct key name to be read
	wchar_t wszKeyName[100] = {0};
	wchar_t wcstringName[50];
	
	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, wcstringName, strlen(szName)+1, szName, _TRUNCATE);
	wcsncat_s(wszKeyName, 100, wcstringName, strlen(szName)+1);	
	wprintf(L"Key Name: %s\n", wszKeyName);

	// Initializing PLSA_UNICODE_STRING structures
	if (!InitLsaString(&lucKeyName, wszKeyName))
	{
		wprintf(L"Failed InitLsaString\n");
		return FALSE;
	}

	// Read the private data from the key
	ntsResult = LsaRetrievePrivateData(PolicyHandle, &lucKeyName, &lucPrivateData);
	if (ntsResult != ERROR_SUCCESS)
	{
		wprintf(L"LsaStorePrivateData failed:\n");
		GetLSAErrorStatus(ntsResult);				
		return FALSE;
	}
	else 
	{
		// lucPrivateData->Buffer : LSA_UNICODE_STRING  buffer might not be null-terminated !
		// lucPrivateData->Length : Length, in bytes, not including the null terminator, if any

		printf("Buffer data len: %d characters. Data: ", lucPrivateData->Length/2);
		CHAR *pBuf = (CHAR *)lucPrivateData->Buffer;
		for(int i=0; i<lucPrivateData->Length; i+=2) {
			printf("%c", pBuf[i]);
		}
	}
	
	LsaFreeMemory(lucPrivateData);
	
	return TRUE;
}

/* 
 * Translate NT status to a windows error code and interpret it
 * 
 * LSA policy function return values
 *  http://msdn.microsoft.com/en-us/library/windows/desktop/ms721859(v=vs.85).aspx#lsa_policy_function_return_values 
 */
void GetLSAErrorStatus(NTSTATUS status){
	ULONG winErrCode = LsaNtStatusToWinError(status);

	switch(winErrCode){
	case ERROR_ACCESS_DENIED:
		printf("Caller does not have the appropriate access to complete the operation\n");
		break;
	case ERROR_NO_SYSTEM_RESOURCES:
		printf("There are not enough system resources to complete the call\n");
		break;
	case ERROR_INTERNAL_DB_ERROR:
		printf("The LSA database contains an internal inconsistency\n");
		break;
	case ERROR_INVALID_HANDLE:
		printf("Indicates an object or RPC handle is not valid in the context used\n");
		break;
	case ERROR_INVALID_SERVER_STATE:
		printf("The LSA server is currently disabled\n");
		break;
	case ERROR_INVALID_PARAMETER:
		printf("One of the parameters is not valid\n");
		break;
	case ERROR_NO_SUCH_PRIVILEGE:
		printf("Indicates a specified privilege does not exist\n");
		break;
	case ERROR_FILE_NOT_FOUND:
		printf("An object in the LSA policy database was not found\n");
		break;
	default:
		printf("Unknown status\n");
		break;
	}
}
