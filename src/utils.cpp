#include <windows.h>
#include <stdio.h>

#include "utils.h"

void dump_bytes(void* v, int size, int as_chars){
    int i = 0;
    unsigned char *array = (unsigned char*) v;

    for (i = 0; i<size; ++i){
        if(!array[i]){
            continue;
        }
        printf(as_chars?"%c":"%02x ", array[i]);
        if( i%16 == 15 && !as_chars) {
            printf("\n");
        }
    }
    printf("\n");
}

char* HandleError(char *msg){
    char *error_buf = NULL;
    int rc = GetLastError();

    FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
            NULL,
            rc,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 	// default language
            (char*) &error_buf,  //error_buf,	// receiving buffer. Allocated with LocalAlloc()
            0, 					 // minimum number of bytes to allocate
            NULL
    );

    printf("%s failure (%d):\n%s", msg, rc, error_buf);
    LocalFree(error_buf);

    return error_buf;
}
