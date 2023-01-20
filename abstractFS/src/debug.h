#include <errno.h>
#include <string.h>

#define FATAL(x...) do { \
    fflush(stdout); \
    printf("\n[-]  SYSTEM ERROR : "); \
    printf("       OS message : %s\n", strerror(errno)); \
    exit(1); \
  } while (0)

/* logs all messages below this level, level 0 turns off LOG 
log_s(1, "fatal error occurred");
log_s(3, "x=%d and name=%s",2, "ali");

output

[1]: fatal error occurred
[3]: x=2 and name=ali
*/

#define LOG_LEVEL_OFF 0
#define LOG_LEVEL_ERR 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_INFO 3
#define LOG_LEVEL_DEBUG 4
#define LOG_LEVEL_VERBOSE 5

#ifndef LOG_LEVEL
#define LOG_LEVEL 4
#endif
#define _LOG_FORMAT_SHORT(letter, format) "[" #letter "]: " format "\n"

/**
 *  short log 
 *  @param level  0:off, 1:error, 2:warning, 3: info, 4: debug, 5:verbose
 */
#define log_s(level, format, ...)     \
    if (level <= LOG_LEVEL)            \
    printf(_LOG_FORMAT_SHORT(level, format), ##__VA_ARGS__)
