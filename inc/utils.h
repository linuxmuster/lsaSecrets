#ifndef __UTILS_H__
#define __UTILS_H__

extern unsigned int log_level;

#define LOG_LEVEL_VERY_VERBOSE      2
#define LOG_LEVEL_VERBOSE           1
#define LOG_LEVEL_NONE              0

#pragma warning( disable: 4127)

#define VERBOSE(code) do { if (log_level >= LOG_LEVEL_VERBOSE) { code } } while( 0 )
#define VVERBOSE(code) do { if (log_level >= LOG_LEVEL_VERY_VERBOSE) {code } } while( 0 )

/* dump bytes as hex or as chars */
void dump_bytes(void* v, int size, int as_chars);

/* handle errors from GetLastError() */
char* HandleError(char *msg);

#endif /* __UTILS_H__ */
