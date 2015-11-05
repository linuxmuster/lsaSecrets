#include <stdio.h>

#include "lsa_util.h"

// Link with the Advapi32.lib file.
#pragma comment (lib, "Advapi32")

int main(int argc, char* argv[])
{
	NTSTATUS status;
	LSA_OBJECT_ATTRIBUTES att;
	LSA_HANDLE pol; 

	memset(&att,0,sizeof(att));

	if ( argc != 3 )
	{
		printf("Syntax: %s <SecretName> <SecretData>\n", argv[0]);
		return 1;
	}

	status=LsaOpenPolicy(NULL, &att, POLICY_ALL_ACCESS, &pol);
	if ( status!=ERROR_SUCCESS )
	{
		GetLSAErrorStatus(status);
		return 2;
	}

	CreatePrivateDataObject(pol, argv[1], argv[2]);

	LsaClose(pol);

	return 0;
}
