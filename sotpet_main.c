
/* SOTPET - Simple One-Trick Pony Encryption Tool */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#if !BSD
#include "linuxfun.h"
#else
#include "bsdfun.h"
#endif
#include "sotpet.h"
#include "whirlpool.h"
#include "sotpet_trailer.h"
#include "sotpet_level2.hpp"
#include "buftools.h"


#define PASSBUF_LEN         512


const char * title = "Simple One-Trick-Pony Encryption Tool (sorbet) V%s\n";
const char * copylight = "(C)2023 Lusers' Malfunctioning Software Association aka. KJ Wolf\n";
const char * usage = "usage: %s  -d|-e|-h  {passwordfile}  < {infile}  > {outfile}\n"
                     "  alt: %s  -d|-e|-h  {passwordfile}    {infile}    {outfile}\n"
             "  -d    decryption\n"
             "  -e    encryption\n"
         /*  "  -p pw password\n"
             "  -P pf password file\n"   */
             "  -h    help\n"
             "\n";
const char * note1 = "\t**ATTENTION**\n"
             "Please be aware of that leaving your passwordfile undeleted / unerased / \n"
             "unwiped on a usual persistent medium might get you into trouble.\n";
const char * help2 = "this tool accepts a pipe in and a pipe out\n";
const char * help4 = "Environment variables:\n\tSORBET_CPUS, SORBET_NUMBLOCKS [512], SORBET_BLOCKSIZE [1024],\n\tSORBET_USE_TRAILER [1]\n";


int main(int argc, char *argv[])
{
    struct trailerset trailer;
    void *sotpet;
    bool encflg;
    int i,r,res=0;
    char passbuf[PASSBUF_LEN];
    FILE *f;
    char *p;

    short cpus;
    int   numblocks    = atoi(getenv_fb("SORBET_NUMBLOCKS", "512"));
    int   blocksize    = atoi(getenv_fb("SORBET_BLOCKSIZE", "1024"));
    bool  use_trailer  = atoi(getenv_fb("SORBET_USE_TRAILER", "1"));

    int ifi = STDIN_FILENO;
    int ofi = STDOUT_FILENO;


    p = getenv("SORBET_CPUS");
    cpus = p ? (atoi(p)) : getcpus();
    fprintf(stderr, "CPUS=%hd\n", cpus);

    fprintf(stderr, title, SOTPET_VERSION);
    fputs(copylight, stderr);
    if(argc>1 && !strcmp(argv[1],"-h"))
    {
        printf(usage, argv[0]);
        puts(help2);
        puts(help4);
        fputs(note1, stdout);
        return 1;
    }

    if(argc<3 && argc!=5)
    {
        fprintf(stderr, usage, argv[0]);
        fputs(note1, stderr);
        return 1;
    }

    encflg = !strcmp(argv[1],"-e");
    if(!encflg && strcmp(argv[1],"-d"))
    {
        fprintf(stderr, "%s: %s: not recognized\n", argv[0], argv[1]);
        return 9;
    }

    f=fopen(argv[2], "rt");
    if(!f)
    {
        perror(argv[2]);
        return 8;
    }
    if(!fgets(passbuf, PASSBUF_LEN, f))
    {
        perror(argv[2]);
        return 7;
    }
    fclose(f);

    if(argc>=5)
    {
        ifi = open(argv[3], O_RDONLY);
        if(ifi<0)
        {
            perror(argv[3]);
            return 11;
        }
        ofi = open(argv[4], O_WRONLY|O_EXCL|O_CREAT, 0600);
        if(ofi<0)
        {
            perror(argv[4]);
            return 10;
        }
    }

    i=strlen(passbuf);
    if(i>0 && passbuf[i-1]=='\n')
        passbuf[--i]=0;
    sotpet = sotpet_init(cpus, "test", passbuf, i, blocksize, 0, !encflg);
    if(!sotpet)
    {
        fprintf(stderr, "sotpet_init() failed\n");
        return 6;
    }
    r = sotpet_f2f_smart(encflg, ifi, ofi, cpus, numblocks, blocksize, use_trailer, &trailer, sotpet);
    if(r)
    {
        fprintf(stderr, "sotpet_f2f_smart() failed (%d)\n", r);
        return 5;
    }
    if(!memcmp(trailer.enc.magic, sotpet_magic_enc, MAGICSIZE) && !memcmp(trailer.enc.magic2, sotpet_magic2_enc, MAGICSIZE2))
    {
        fprintf(stderr, "trailer detected\n");
        if(!memcmp(trailer.enc.hash, trailer.hash, HASHSIZE))
            fprintf(stderr, "checksum okay\n");
        else
        {
            fprintf(stderr, "checksum DIFFERS\n");
            res=1;
        }
    }
    else
        res=encflg?0:2;
    sotpet_exit(sotpet);
    fprintf(stderr, "return value = %d\n", res);
    return res;
}
