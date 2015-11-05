#ifndef __LSA_UTIL_H__
#define __LSA_UTIL_H__

#include <windows.h>
#include <NTSecAPI.h>

BOOL InitLsaString(
		PLSA_UNICODE_STRING pLsaString,	// destination
		LPCWSTR pwszString				// source (Unicode)
);

BOOL CreatePrivateDataObject(
		LSA_HANDLE PolicyHandle,
		CHAR *szName,			// name of the key
		CHAR *szPrvData			// private data to store
);

BOOL ReadPrivateDataObject(
		LSA_HANDLE PolicyHandle,
		CHAR *szName			// name of the key
);

void GetLSAErrorStatus(
		NTSTATUS Status
);

#endif /* __LSA_UTIL_H__ */
