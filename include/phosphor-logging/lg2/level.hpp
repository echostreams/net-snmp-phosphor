#pragma once

#if defined(__linux__)
#include <syslog.h>
#else
#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */
#endif

namespace lg2
{

enum class level
{
    emergency = LOG_EMERG,
    alert = LOG_ALERT,
    critical = LOG_CRIT,
    error = LOG_ERR,
    warning = LOG_WARNING,
    notice = LOG_NOTICE,
    info = LOG_INFO,
    debug = LOG_DEBUG,
};

}
