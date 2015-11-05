#include <stdio.h>

#include "lsa_util.h"

// Link with the Advapi32.lib file.
#pragma comment (lib, "Advapi32")

int main(int argc, char* argv[])
{
	NTSTATUS status;
	LSA_OBJECT_ATTRIBUTES att;
	LSA_HANDLE pol; 

	if ( argc != 2 )
	{
		printf("Syntax: %s <SecretName> \n", argv[0]);
		return 1;
	}
	memset(&att,0,sizeof(att));

	status=LsaOpenPolicy(NULL, &att, POLICY_ALL_ACCESS, &pol);
	if ( status!=ERROR_SUCCESS )
	{
		GetLSAErrorStatus(status);
		return 2;
	}

	ReadPrivateDataObject(pol, argv[1]);

	LsaClose(pol);

	return 0;
}
