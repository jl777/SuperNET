#include <unistd.h>
#include <sys/stat.h>
#include "auto_home.h"
#include "strerr.h"
#include "error.h"
#include "open.h"
#include "readwrite.h"
#include "exit.h"
#include "buffer.h"
#define FATAL "install: fatal: "

static void h(char *home,int uid,int gid,int mode)
{
    if (mkdir(home,0700) == -1)
        if (errno != error_exist)
            strerr_die4sys(111,FATAL,"unable to mkdir ",home,": ");
    if (chown(home,uid,gid) == -1)
        strerr_die4sys(111,FATAL,"unable to chown ",home,": ");
    if (chmod(home,mode) == -1)
        strerr_die4sys(111,FATAL,"unable to chmod ",home,": ");
}

static void d(char *home,char *subdir,int uid,int gid,int mode)
{
    if (chdir(home) == -1)
        strerr_die4sys(111,FATAL,"unable to switch to ",home,": ");
    if (mkdir(subdir,0700) == -1)
        if (errno != error_exist)
            strerr_die6sys(111,FATAL,"unable to mkdir ",home,"/",subdir,": ");
    if (chown(subdir,uid,gid) == -1)
        strerr_die6sys(111,FATAL,"unable to chown ",home,"/",subdir,": ");
    if (chmod(subdir,mode) == -1)
        strerr_die6sys(111,FATAL,"unable to chmod ",home,"/",subdir,": ");
}

static char inbuf[BUFFER_INSIZE];
static char outbuf[BUFFER_OUTSIZE];
static buffer ssin;
static buffer ssout;
int fdsourcedir = -1;

static void c(char *home,char *subdir,char *file,int uid,int gid,int mode)
{
    int fdin;
    int fdout;
    
    if (fchdir(fdsourcedir) == -1)
        strerr_die2sys(111,FATAL,"unable to switch back to source directory: ");
    
    fdin = open_read(file);
    if (fdin == -1)
        strerr_die4sys(111,FATAL,"unable to read ",file,": ");
    buffer_init(&ssin,read,fdin,inbuf,sizeof inbuf);
    
    if (chdir(home) == -1)
        strerr_die4sys(111,FATAL,"unable to switch to ",home,": ");
    if (chdir(subdir) == -1)
        strerr_die6sys(111,FATAL,"unable to switch to ",home,"/",subdir,": ");
    
    fdout = open_trunc(file);
    if (fdout == -1)
        strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
    buffer_init(&ssout,write,fdout,outbuf,sizeof outbuf);
    
    switch(buffer_copy(&ssout,&ssin)) {
        case -2:
            strerr_die4sys(111,FATAL,"unable to read ",file,": ");
        case -3:
            strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
    }
    
    close(fdin);
    if (buffer_flush(&ssout) == -1)
        strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
    if (fsync(fdout) == -1)
        strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
    if (close(fdout) == -1) /* NFS silliness */
        strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
    
    if (chown(file,uid,gid) == -1)
        strerr_die6sys(111,FATAL,"unable to chown .../",subdir,"/",file,": ");
    if (chmod(file,mode) == -1)
        strerr_die6sys(111,FATAL,"unable to chmod .../",subdir,"/",file,": ");
}

void hier()
{
    h(auto_home,-1,-1,02755);
    d(auto_home,"bin",-1,-1,02755);
    
    c(auto_home,"bin","cdbget",-1,-1,0755);
    c(auto_home,"bin","cdbmake",-1,-1,0755);
    c(auto_home,"bin","cdbdump",-1,-1,0755);
    c(auto_home,"bin","cdbstats",-1,-1,0755);
    c(auto_home,"bin","cdbtest",-1,-1,0755);
    c(auto_home,"bin","cdbmake-12",-1,-1,0755);
    c(auto_home,"bin","cdbmake-sv",-1,-1,0755);
}
