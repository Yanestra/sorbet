
#include <unistd.h>

short getcpus(void)
{
    return sysconf(_SC_NPROCESSORS_ONLN);;
}
