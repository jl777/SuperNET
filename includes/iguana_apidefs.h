
#define IGUANA_CALLARGS myinfo,coin,json,remoteaddr
#define IGUANA_ARGS struct supernet_info *myinfo,struct iguana_info *coin,cJSON *json,char *remoteaddr
#define IGUANA_CFUNC0(agent,name) char *agent ## _ ## name(IGUANA_ARGS)
#define IGUANA_CFUNC_S(agent,name,str) char *agent ## _ ## name(IGUANA_ARGS,char *str)
#define IGUANA_CFUNC_I(agent,name,val) char *agent ## _ ## name(IGUANA_ARGS,int32_t val)
#define IGUANA_CFUNC_SA(agent,name,str,array) char *agent ## _ ## name(IGUANA_ARGS,char *str,cJSON *array)
#define IGUANA_CFUNC_SD(agent,name,str,val) char *agent ## _ ## name(IGUANA_ARGS,char *str,double val)
#define IGUANA_CFUNC_AA(agent,name,array,array2) char *agent ## _ ## name(IGUANA_ARGS,cJSON *array,cJSON *array2)
#define IGUANA_CFUNC_AOI(agent,name,array,object,val) char *agent ## _ ## name(IGUANA_ARGS,cJSON *array,cJSON *object,int32_t val)
#define IGUANA_CFUNC_SAA(agent,name,str,array,array2) char *agent ## _ ## name(IGUANA_ARGS,char *str,cJSON *array,cJSON *array2)

#define IGUANA_CFUNC_64A(agent,name,j64,array) char *agent ## _ ## name(IGUANA_ARGS,uint64_t j64,cJSON *array)
#define IGUANA_CFUNC_SHI_SDSD_II_SSSSSS(agent,name,str,hash,val,str2,amount,str3,amount2,val2,val3,str4,str5,str6,str7,str8,str9) char *agent ## _ ## name(IGUANA_ARGS,char *str,bits256 hash,int32_t val,char *str2,double amount,char *str3,double amount2,int32_t val2,int32_t val3,char *str4,char *str5,char *str6,char *str7,char *str8,char *str9)

#define IGUANA_CFUNC_IA(agent,name,val,array) char *agent ## _ ## name(IGUANA_ARGS,int32_t val,cJSON *array)
#define IGUANA_CFUNC_IAS(agent,name,val,array,str) char *agent ## _ ## name(IGUANA_ARGS,int32_t val,cJSON *array,char *str)
#define IGUANA_CFUNC_II(agent,name,val,val2) char *agent ## _ ## name(IGUANA_ARGS,int32_t val,int32_t val2)
#define IGUANA_CFUNC_III(agent,name,val,val2,val3) char *agent ## _ ## name(IGUANA_ARGS,int32_t val,int32_t val2,int32_t val3)
#define IGUANA_CFUNC_SIII(agent,name,str,val,val2,val3) char *agent ## _ ## name(IGUANA_ARGS,char *str,int32_t val,int32_t val2,int32_t val3)
#define IGUANA_CFUNC_IIA(agent,name,val,val2,array) char *agent ## _ ## name(IGUANA_ARGS,int32_t val,int32_t val2,cJSON *array)
#define IGUANA_CFUNC_SS(agent,name,str,str2) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2)
#define IGUANA_CFUNC_SSI(agent,name,str,str2,val) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,int32_t val)
#define IGUANA_CFUNC_SSH(agent,name,str,str2,hash) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,bits256 hash)
#define IGUANA_CFUNC_SSHI(agent,name,str,str2,hash,val) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,bits256 hash,int32_t val)
#define IGUANA_CFUNC_SSDD(agent,name,str,str2,val,val2) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,double val,double val2)
#define IGUANA_CFUNC_SSHII(agent,name,str,str2,hash,val,val2) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,bits256 hash,int32_t val,int32_t val2)
#define IGUANA_CFUNC_SSHHII(agent,name,str,str2,hash,hash2,val,val2) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,bits256 hash,bits256 hash2,int32_t val,int32_t val2)
#define IGUANA_CFUNC_SSS(agent,name,str,str2,str3) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,char *str3)
#define IGUANA_CFUNC_SDD(agent,name,str,val,val2) char *agent ## _ ## name(IGUANA_ARGS,char *str,double val,double val2)
#define IGUANA_CFUNC_SSSS(agent,name,str,str2,str3,str4) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,char *str3,char *str4)
#define IGUANA_CFUNC_SSSD(agent,name,str,str2,str3,val) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,char *str3,double val)
#define IGUANA_CFUNC_SSSDDD(agent,name,str,str2,str3,val,val2,val3) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,char *str3,double val,double val2,double val3)
#define IGUANA_CFUNC_SSSIII(agent,name,str,str2,str3,val,val2,val3) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,char *str3,int32_t val,int32_t val2,int32_t val3)

#define IGUANA_CFUNC_SI(agent,name,str,val) char *agent ## _ ## name(IGUANA_ARGS,char *str,int32_t val)
#define IGUANA_CFUNC_SII(agent,name,str,val,val2) char *agent ## _ ## name(IGUANA_ARGS,char *str,int32_t val,int32_t val2)
#define IGUANA_CFUNC_HI(agent,name,hash,val) char *agent ## _ ## name(IGUANA_ARGS,bits256 hash,int32_t val)
#define IGUANA_CFUNC_H(agent,name,hash) char *agent ## _ ## name(IGUANA_ARGS,bits256 hash)
#define IGUANA_CFUNC_HS(agent,name,hash,str) char *agent ## _ ## name(IGUANA_ARGS,bits256 hash,char *str)
#define IGUANA_CFUNC_HA(agent,name,hash,array) char *agent ## _ ## name(IGUANA_ARGS,bits256 hash,cJSON *array)
#define IGUANA_CFUNC_HH(agent,name,hash,hash2) char *agent ## _ ## name(IGUANA_ARGS,bits256 hash,bits256 hash2)
#define IGUANA_CFUNC_HHS(agent,name,hash,hash2,str) char *agent ## _ ## name(IGUANA_ARGS,bits256 hash,bits256 hash2,char *str)
#define IGUANA_CFUNC_HAS(agent,name,hash,array,str) char *agent ## _ ## name(IGUANA_ARGS,bits256 hash,cJSON *array,char *str)
#define IGUANA_CFUNC_HII(agent,name,hash,val,val2) char *agent ## _ ## name(IGUANA_ARGS,bits256 hash,int32_t val,int32_t val2)
#define IGUANA_CFUNC_D(agent,name,val) char *agent ## _ ## name(IGUANA_ARGS,double val)
#define IGUANA_CFUNC_SSDIS(agent,name,str,str2,amount,val,str3) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,double amount,int32_t val,char *str3)
#define IGUANA_CFUNC_SSDISS(agent,name,str,str2,amount,val,str3,str4) char *agent ## _ ## name(IGUANA_ARGS,char *str,char *str2,double amount,int32_t val,char *str3,char *str4)
#define IGUANA_CFUNC_SAIS(agent,name,str,array,val,str2) char *agent ## _ ## name(IGUANA_ARGS,char *str,cJSON *array,int32_t val,char *str2)
#define IGUANA_CFUNC_SAOS(agent,name,str,array,object,str2) char *agent ## _ ## name(IGUANA_ARGS,char *str,cJSON *array,cJSON *object,char *str2)
#define IGUANA_CFUNC_SDSS(agent,name,str,amount,str2,str3) char *agent ## _ ## name(IGUANA_ARGS,char *str,double amount,char *str2,char *str3)

// API functions
#define ZERO_ARGS IGUANA_CFUNC0
#define INT_ARG IGUANA_CFUNC_I
#define TWO_INTS IGUANA_CFUNC_II
#define STRING_ARG IGUANA_CFUNC_S
#define TWO_STRINGS IGUANA_CFUNC_SS
#define THREE_STRINGS IGUANA_CFUNC_SSS
#define FOUR_STRINGS IGUANA_CFUNC_SSSS
#define STRING_AND_INT IGUANA_CFUNC_SI
#define STRING_AND_DOUBLE IGUANA_CFUNC_SD
#define STRING_AND_TWOINTS IGUANA_CFUNC_SII
#define HASH_AND_INT IGUANA_CFUNC_HI
#define HASH_AND_STRING IGUANA_CFUNC_HS
#define TWOHASHES_AND_STRING IGUANA_CFUNC_HHS
#define HASH_AND_TWOINTS IGUANA_CFUNC_HII
#define DOUBLE_ARG IGUANA_CFUNC_D
#define STRING_AND_ARRAY IGUANA_CFUNC_SA
#define STRING_AND_TWOARRAYS IGUANA_CFUNC_SAA
#define TWO_ARRAYS IGUANA_CFUNC_AA
#define ARRAY_OBJ_INT IGUANA_CFUNC_AOI
#define STRING_ARRAY_OBJ_STRING IGUANA_CFUNC_SAOS
#define INT_AND_ARRAY IGUANA_CFUNC_IA
#define INT_ARRAY_STRING IGUANA_CFUNC_IAS
#define SS_D_I_S IGUANA_CFUNC_SSDIS
#define SS_D_I_SS IGUANA_CFUNC_SSDISS
#define S_A_I_S IGUANA_CFUNC_SAIS
#define S_D_SS IGUANA_CFUNC_SDSS
#define TWOINTS_AND_ARRAY IGUANA_CFUNC_IIA
#define STRING_AND_THREEINTS IGUANA_CFUNC_SIII
#define TWOSTRINGS_AND_INT IGUANA_CFUNC_SSI
#define TWOSTRINGS_AND_HASH IGUANA_CFUNC_SSH
#define TWOSTRINGS_AND_HASH_AND_TWOINTS IGUANA_CFUNC_SSHII
#define TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS IGUANA_CFUNC_SSHHII
#define THREE_INTS IGUANA_CFUNC_III
#define HASH_ARRAY_STRING IGUANA_CFUNC_HAS
#define U64_AND_ARRAY IGUANA_CFUNC_64A
#define HASH_ARG IGUANA_CFUNC_H
#define HASH_AND_ARRAY IGUANA_CFUNC_HA
#define TWO_HASHES IGUANA_CFUNC_HH
#define THREE_STRINGS_AND_THREE_INTS IGUANA_CFUNC_SSSIII
#define THREE_STRINGS_AND_THREE_DOUBLES IGUANA_CFUNC_SSSDDD
#define THREE_STRINGS_AND_DOUBLE IGUANA_CFUNC_SSSD
#define TWO_STRINGS_AND_TWO_DOUBLES IGUANA_CFUNC_SSDD
#define STRING_AND_TWO_DOUBLES IGUANA_CFUNC_SDD
#define P2SH_SPENDAPI IGUANA_CFUNC_SHI_SDSD_II_SSSSSS

