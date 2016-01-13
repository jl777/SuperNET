
#define IGUANA_ARGS struct supernet_info *myinfo,struct iguana_info *coin
#define IGUANA_CFUNC0(name) char *iguana_ ## name(IGUANA_ARGS)
#define IGUANA_CFUNC_S(name,str) char *iguana_ ## name(IGUANA_ARGS,char *str)
#define IGUANA_CFUNC_I(name,val) char *iguana_ ## name(IGUANA_ARGS,int32_t val)
#define IGUANA_CFUNC_SA(name,str,array) char *iguana_ ## name(IGUANA_ARGS,char *str,cJSON *array)
#define IGUANA_CFUNC_AA(name,array,array2) char *iguana_ ## name(IGUANA_ARGS,cJSON *array,cJSON *array2)
#define IGUANA_CFUNC_SAA(name,str,array,array2) char *iguana_ ## name(IGUANA_ARGS,char *str,cJSON *array,cJSON *array2)
#define IGUANA_CFUNC_IA(name,val,array) char *iguana_ ## name(IGUANA_ARGS,int32_t val,cJSON *array)
#define IGUANA_CFUNC_IAS(name,val,array,str) char *iguana_ ## name(IGUANA_ARGS,int32_t val,cJSON *array,char *str)
#define IGUANA_CFUNC_II(name,val,val2) char *iguana_ ## name(IGUANA_ARGS,int32_t val,int32_t val2)
#define IGUANA_CFUNC_SS(name,str,str2) char *iguana_ ## name(IGUANA_ARGS,char *str,char *str2)
#define IGUANA_CFUNC_SSS(name,str,str2,str3) char *iguana_ ## name(IGUANA_ARGS,char *str,char *str2,char *str3)
#define IGUANA_CFUNC_SI(name,str,val) char *iguana_ ## name(IGUANA_ARGS,char *str,int32_t val)
#define IGUANA_CFUNC_SII(name,str,val,val2) char *iguana_ ## name(IGUANA_ARGS,char *str,int32_t val,int32_t val2)
#define IGUANA_CFUNC_HI(name,hash,val) char *iguana_ ## name(IGUANA_ARGS,bits256 hash,int32_t val)
#define IGUANA_CFUNC_HII(name,hash,val,val2) char *iguana_ ## name(IGUANA_ARGS,bits256 hash,int32_t val,int32_t val2)
#define IGUANA_CFUNC_D(name,val) char *iguana_ ## name(IGUANA_ARGS,double val)
#define IGUANA_CFUNC_SSDIS(name,str,str2,amount,val,str3) char *iguana_ ## name(IGUANA_ARGS,char *str,char *str2,double amount,int32_t val,char *str3)
#define IGUANA_CFUNC_SSDISS(name,str,str2,amount,val,str3,str4) char *iguana_ ## name(IGUANA_ARGS,char *str,char *str2,double amount,int32_t val,char *str3,char *str4)
#define IGUANA_CFUNC_SAIS(name,str,array,val,str2) char *iguana_ ## name(IGUANA_ARGS,char *str,cJSON *array,int32_t val,char *str2)
#define IGUANA_CFUNC_SDSS(name,str,amount,str2,str3) char *iguana_ ## name(IGUANA_ARGS,char *str,double amount,char *str2,char *str3)

// API functions
#define ZERO_ARGS IGUANA_CFUNC0
#define INT_ARG IGUANA_CFUNC_I
#define TWO_INTS IGUANA_CFUNC_II
#define STRING_ARG IGUANA_CFUNC_S
#define TWO_STRINGS IGUANA_CFUNC_SS
#define THREE_STRINGS IGUANA_CFUNC_SSS
#define STRING_AND_INT IGUANA_CFUNC_SI
#define STRING_AND_TWOINTS IGUANA_CFUNC_SII
#define HASH_AND_INT IGUANA_CFUNC_HI
#define HASH_AND_TWOINTS IGUANA_CFUNC_HII
#define DOUBLE_ARG IGUANA_CFUNC_D
#define STRING_AND_ARRAY IGUANA_CFUNC_SA
#define STRING_AND_TWOARRAYS IGUANA_CFUNC_SAA
#define TWO_ARRAYS IGUANA_CFUNC_AA
#define INT_AND_ARRAY IGUANA_CFUNC_IA
#define INT_ARRAY_STRING IGUANA_CFUNC_IAS
#define SS_D_I_S IGUANA_CFUNC_SSDIS
#define SS_D_I_SS IGUANA_CFUNC_SSDISS
#define S_A_I_S IGUANA_CFUNC_SAIS
#define S_D_SS IGUANA_CFUNC_SDSS
