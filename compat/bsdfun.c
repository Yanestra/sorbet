
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/sysctl.h>

#include "bsdfun.h"


ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
{
    int r, f = open("/dev/urandom", O_RDONLY);
    if(f<0)
        abort();

    r = read(f, buf, buflen);
    close(f);
    return r;
}


/* I dunno if that's shit I copied it from stackoverflow post, it looks quite shitty
 * but somewhat reasonable.  I have tested with 2 architectures with NetBSD and AMD64 Linux.
 */

short getcpus(void)
{
    int mib[4];
    short numCPU = -1;
    size_t len = sizeof(numCPU);

    /* set the mib for hw.ncpu */
    mib[0] = CTL_HW;
    mib[1] = HW_NCPU;
    sysctl(mib, 2, &numCPU, &len, NULL, 0);
    if (numCPU < 1)
        numCPU = 1;
    return numCPU;
}
