
CRYPTO777 = agents/libcrypto777.a
IGUANA = agents/iguana
INSTANTDEX = agents/InstantDEX
PAX = agents/PAX
PRICES = agents/prices
PANGEA = agents/pangea
TRADEBOTS = agents/tradebots
SUPERNET = agents/SuperNET

DEPS =

CFLAGS = -Wall -Wno-deprecated -Wno-unused-function -fno-strict-aliasing

LIBS = ../agents/libcrypto777.a -lcurl -lssl -lcrypto -lpthread -lz -lm

CC = gcc
OS := $(shell uname -s)
ifeq ($(OSNAME),Linux)
CFLAGS += -Wno-unused-but-set-variable
endif

CFLAGS +=  -O2


all: $(CRYPTO777) $(IGUANA) $(TRADEBOTS) $(SUPERNET) # $(INSTANTDEX) $(PAX) $(PRICES) $(PANGEA)

$(CRYPTO777):  crypto777/OS_nonportable.c crypto777/OS_portable.c crypto777/OS_time.c crypto777/iguana_OS.c crypto777/OS_portable.h crypto777/iguana_utils.c crypto777/bitcoind_RPC.c crypto777/cJSON.c crypto777/curve25519-donna.c crypto777/curve25519.c crypto777/hmac_sha512.c crypto777/inet.c crypto777/libgfshare.c crypto777/ramcoder.c crypto777/SaM.c crypto777/jpeg/jaricom.c crypto777/jpeg/jcapimin.c crypto777/jpeg/jcapistd.c crypto777/jpeg/jcarith.c crypto777/jpeg/jccoefct.c crypto777/jpeg/jccolor.c \
        crypto777/jpeg/jcdctmgr.c crypto777/jpeg/jchuff.c crypto777/jpeg/jcinit.c crypto777/jpeg/jcmainct.c crypto777/jpeg/jcmarker.c crypto777/jpeg/jcmaster.c \
        crypto777/jpeg/jcomapi.c crypto777/jpeg/jcparam.c crypto777/jpeg/jcprepct.c crypto777/jpeg/jcsample.c crypto777/jpeg/jctrans.c crypto777/jpeg/jdapimin.c \
        crypto777/jpeg/jdapistd.c crypto777/jpeg/jdarith.c crypto777/jpeg/jdatadst.c crypto777/jpeg/jdatasrc.c crypto777/jpeg/jdcoefct.c crypto777/jpeg/jdcolor.c \
        crypto777/jpeg/jddctmgr.c crypto777/jpeg/jdhuff.c crypto777/jpeg/jdinput.c crypto777/jpeg/jdmainct.c crypto777/jpeg/jdmarker.c crypto777/jpeg/jdmaster.c \
        crypto777/jpeg/jdmerge.c crypto777/jpeg/jdpostct.c crypto777/jpeg/jdsample.c crypto777/jpeg/jdtrans.c crypto777/jpeg/jerror.c crypto777/jpeg/jfdctflt.c \
        crypto777/jpeg/jfdctfst.c crypto777/jpeg/jfdctint.c crypto777/jpeg/jidctflt.c crypto777/jpeg/jidctfst.c crypto777/jpeg/jidctint.c crypto777/jpeg/jquant1.c \
        crypto777/jpeg/jquant2.c crypto777/jpeg/jutils.c crypto777/jpeg/jmemmgr.c crypto777/jpeg/jmemnobs.c;  \
   cd crypto777; gcc -c -O2 *.c jpeg/jaricom.c jpeg/jcapimin.c jpeg/jcapistd.c jpeg/jcarith.c jpeg/jccoefct.c jpeg/jccolor.c \
        jpeg/jcdctmgr.c jpeg/jchuff.c jpeg/jcinit.c jpeg/jcmainct.c jpeg/jcmarker.c jpeg/jcmaster.c \
        jpeg/jcomapi.c jpeg/jcparam.c jpeg/jcprepct.c jpeg/jcsample.c jpeg/jctrans.c jpeg/jdapimin.c \
        jpeg/jdapistd.c jpeg/jdarith.c jpeg/jdatadst.c jpeg/jdatasrc.c jpeg/jdcoefct.c jpeg/jdcolor.c \
        jpeg/jddctmgr.c jpeg/jdhuff.c jpeg/jdinput.c jpeg/jdmainct.c jpeg/jdmarker.c jpeg/jdmaster.c \
        jpeg/jdmerge.c jpeg/jdpostct.c jpeg/jdsample.c jpeg/jdtrans.c jpeg/jerror.c jpeg/jfdctflt.c \
        jpeg/jfdctfst.c jpeg/jfdctint.c jpeg/jidctflt.c jpeg/jidctfst.c jpeg/jidctint.c jpeg/jquant1.c \
        jpeg/jquant2.c jpeg/jutils.c jpeg/jmemmgr.c jpeg/jmemnobs.c; \
        ar rcu ../agents/libcrypto777.a *.o jpeg/*.o; cd ..

$(IGUANA): ;\
    cd iguana; $(CC) -o ../agents/iguana *.c $(LIBS); make; cd ..

$(SUPERNET): ;\
    cd SuperNET; $(CC) -o ../agents/SuperNET *.c $(LIBS); make; cd ..

$(INSTANTDEX): ;\
    cd InstantDEX; $(CC) -o ../agents/InstantDEX *.c $(LIBS); make; cd ..

$(PANGEA):  ;\
    cd pangea; $(CC) -o ../agents/pangea *.c $(LIBS); make; cd ..

$(TRADEBOTS):  ;\
    cd tradebots; $(CC) -o ../agents/tradebots *.c $(LIBS); make; cd ..

$(PRICES):  ;\
    cd pangea; $(CC) -o ../agents/pangea *.c $(LIBS); make; cd ..

$(PAX):  ;\
    cd peggy; $(CC) -o ../agents/PAX *.c $(LIBS); make; cd ..

iguana: $(IGUANA)
SN: $(SuperNET)
idex: $(InstantDEX)
PAX: $(PAX)
prices: $(PRICES)
pangea: $(PANGEA)
lib: $(CRYPTO777)

doesntexist:

clean: doesntexist; \
   rm agents/*; cd crypto777; rm *.o jpeg/*.o; make clean; cd ..; cd iguana; make clean; cd ..; cd SuperNET; make clean; cd ..; cd InstantDEX; make clean; cd ..; cd pangea; make clean; cd ..; cd prices; make clean; cd ..; cd tradebots; make clean; cd ..
