#define USE_BASIC_CONFIG 1
#define USE_NUM_GMP 1
#define USE_FIELD_10X26 1

#define USE_NUM_NONE 1
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1
#include "secp256k1/libsecp256k1-config.h"

#include "secp256k1/secp256k1.h"

#include "secp256k1/util.h"
#include "secp256k1/scalar.h"
#include "secp256k1/scalar_4x64.h"
#include "secp256k1/scalar_8x32.h"
#include "secp256k1/scalar_impl.h"
#include "secp256k1/scalar_4x64_impl.h"
#include "secp256k1/scalar_8x32_impl.h"
#include "secp256k1/group.h"
#include "secp256k1/group_impl.h"
#include "secp256k1/num_gmp.h"
#include "secp256k1/num_gmp_impl.h"
#include "secp256k1/ecdsa.h"
#include "secp256k1/ecdsa_impl.h"
#include "secp256k1/eckey.h"
#include "secp256k1/eckey_impl.h"
#include "secp256k1/ecmult.h"
#include "secp256k1/ecmult_impl.h"
#include "secp256k1/ecmult_const.h"
#include "secp256k1/ecmult_const_impl.h"
#include "secp256k1/ecmult_gen.h"
#include "secp256k1/ecmult_gen_impl.h"
#include "secp256k1/num.h"
#include "secp256k1/num_impl.h"
#include "secp256k1/field_10x26.h"
#include "secp256k1/field_10x26_impl.h"
#include "secp256k1/field_5x52.h"
#include "secp256k1/field_5x52_impl.h"
#include "secp256k1/field_5x52_int128_impl.h"
#include "secp256k1/field_5x52_asm_impl.h"
#include "secp256k1/java/org_bitcoin_NativeSecp256k1.h"
#include "secp256k1/testrand.h"
#include "secp256k1/testrand_impl.h"
#include "secp256k1/hash.h"
#include "secp256k1/hash_impl.h"
#include "secp256k1/field.h"
#include "secp256k1/field_impl.h"
#include "secp256k1/bench.h"

#include "secp256k1/secp256k1.c"

