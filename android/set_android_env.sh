#!/bin/bash

#      _           _      _             _     _
#     | |_   _ ___| |_   / \   _ __ ___| |__ (_)
#  _  | | | | / __| __| / _ \ | '__/ __| '_ \| |
# | |_| | |_| \__ \ |_ / ___ \| | | (__| | | | |
#  \___/ \__,_|___/\__/_/   \_\_|  \___|_| |_|_|
#
# Copyright 2014-2015 Łukasz "JustArchi" Domeradzki
# Contact: JustArchi@JustArchi.net
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#############
### BASIC ###
#############

# Root of NDK, the one which contains $NDK/ndk-build binary
NDK="/home/user/ndk"

# Example command to build standalone toolchain:
# user@machine:ndk# build/tools/make-standalone-toolchain.sh --toolchain=arm-linux-androideabi-4.9 --platform=android-21 --install-dir=/home/user/ndkTC
# Root of NDK toolchain, the one used in --install-dir from $NDK/build/tools/make-standalone-toolchain.sh. Make sure it contains $NDKTC/bin directory with $CROSS_COMPILE binaries
NDKTC="/home/user/ndkTC"

# Optional, may help NDK in some cases
export NDK_TOOLCHAIN_VERSION=4.9
export SYSROOT="$NDKTC/sysroot"

# This flag turns on ADVANCED section below, you should use "0" if you want easy compiling for generic targets, or "1" if you want to get best optimized results for specific targets
# In general it's strongly suggested to leave it turned on, but if you're using makefiles, which already specify optimization level and everything else, then of course you may want to turn it off
ADVANCED="1"

################
### ADVANCED ###
################

# Defaults
MARCH="armv7-a"
MFPU="neon"
MFLOATABI="hard"

FLTO=1

for ARG in "$@"; do
	case "$ARG" in
		--march=*) MARCH="$(echo "$ARG" | cut -d '=' -f 2-)" ;;
		--mfpu=*) MFPU="$(echo "$ARG" | cut -d '=' -f 2-)" ;;
		--mfloat-abi=*) MFLOATABI="$(echo "$ARG" | cut -d '=' -f 2-)" ;;
		--no-flto) FLTO=0 ;;
	esac
done

# Device CFLAGS, these should be taken from TARGET_GLOBAL_CFLAGS property of BoardCommonConfig.mk of your device, eventually leave them empty for generic non-device-optimized build
# Please notice that -march flag comes from TARGET_ARCH_VARIANT
DEVICECFLAGS="-march=$MARCH -mfpu=$MFPU -mfloat-abi=$MFLOATABI"

# This specifies optimization level used during compilation. Usually it's a good idea to keep it on "-O2" for best results, but you may want to experiment with "-Os", "-O3" or "-Ofast"
OLEVEL="-O3"

# This specifies extra optimization flags, which are not selected by any of optimization levels chosen above
# Please notice that they're pretty EXPERIMENTAL, and if you get any compilation errors, the first step is experimenting with them or disabling them completely, you may also want to try different O level

# Main ArchiDroid Optimizations flags
OPTICFLAGS="-fgcse-las -fgcse-sm -fipa-pta -fivopts -fomit-frame-pointer -frename-registers -fsection-anchors -ftracer -ftree-loop-im -ftree-loop-ivcanon -funsafe-loop-optimizations -funswitch-loops -fweb"

# Graphgite ArchiDroid Optimization flags
OPTICFLAGS+=" -fgraphite -fgraphite-identity"

# Extra ArchiDroid ICE flags
OPTICFLAGS+=" -floop-block -floop-interchange -floop-nest-optimize -floop-parallelize-all -floop-strip-mine -fmodulo-sched -fmodulo-sched-allow-regmoves"

# Extra Android flags
OPTICFLAGS+=" -ffunction-sections -fdata-sections -fvisibility=hidden -s"

# This specifies extra linker optimizations. Same as above, in case of problems this is second step for finding out the culprit
LDFLAGS="-llog -Wl,-O3 -Wl,--as-needed -Wl,--relax -Wl,--sort-common -Wl,--gc-sections"

# This specifies additional sections to strip, for extra savings on size
STRIPFLAGS="-s -R .note -R .comment -R .gnu.version -R .gnu.version_r"

# Additional definitions, which may help some binaries to work with android
DEFFLAGS="-fPIC -fPIE -pie -DNDEBUG -D__ANDROID__ -DANDROID"

if [[ "$FLTO" -eq 1 ]]; then
	OPTICFLAGS+=" -flto"
	LDFLAGS+=" -Wl,-flto"
fi

##############
### EXPERT ###
##############

# This specifies host (target) for makefiles. In some rare scenarios you may also try "--host=arm-linux-androideabi"
# In general you shouldn't change that, as you're compiling binaries for low-level ARM-EABI and not Android itself
CONFIGANDROID="--host=arm-linux-eabi --with-sysroot=$SYSROOT"

# This specifies the CROSS_COMPILE variable, again, in some rare scenarios you may also try "arm-eabi-"
# But beware, NDK doesn't even offer anything apart from arm-linux-androideabi one, however custom toolchains such as Linaro offer arm-eabi as well
CROSS_COMPILE="arm-linux-androideabi-"

# This specifies if we should also override our native toolchain in the PATH in addition to overriding makefile commands such as CC
# You should NOT enable it, unless your makefile calls "gcc" instead of "$CC" and you want to point "gcc" (and similar) to NDKTC
# However, in such case, you should either fix makefile yourself or not use it at all
# You've been warned, this is not a good idea
TCOVERRIDE="0"

# Workaround for some broken compilers with malloc problems (undefined reference to rpl_malloc and similar errors during compiling), don't uncomment unless you need it
#export ac_cv_func_malloc_0_nonnull=yes

############
### CORE ###
############

# You shouldn't edit anything from now on
export CROSS_COMPILE="$CROSS_COMPILE" # All makefiles depend on CROSS_COMPILE variable, this is important to set"

if [[ "$ADVANCED" -ne 0 ]]; then # If advanced is specified, we override flags used by makefiles with our optimized ones, of course if makefile allows that
	CFLAGS="$OLEVEL $DEVICECFLAGS $OPTICFLAGS $DEFFLAGS --sysroot=$SYSROOT"
	CXXFLAGS="$CFLAGS" # We use same flags for CXX as well
	CPPFLAGS="$CPPFLAGS" # Yes, CPP is the same as CXX, because they're both used in different makefiles/compilers, unfortunately

	export CFLAGS="$CFLAGS"
	export LOCAL_CFLAGS="$CFLAGS"
	export CXXFLAGS="$CFLAGS" # We use same flags for CXX as well
	export LOCAL_CXXFLAGS="$CXXFLAGS"
	export CPPFLAGS="$CPPFLAGS" # Yes, CPP is the same as CXX, because they're both used in different makefiles/compilers, unfortunately
	export LOCAL_CPPFLAGS="$CPPFLAGS"
	export LDFLAGS="$LDFLAGS"
	export LOCAL_LDFLAGS="$LDFLAGS"
else
	unset CFLAGS
	unset CXXFLAGS
	unset CPPFLAGS
	unset LDFLAGS
fi

if [[ -n "$NDK" && -d "$NDK" ]] && ! echo "$PATH" | grep -q "$NDK"; then # If NDK doesn't exist in the path (yet), prepend it
	export PATH="$NDK:$PATH"
fi

if [[ -n "$NDKTC" && -d "$NDKTC" ]] && ! echo "$PATH" | grep -q "$NDKTC"; then # If NDKTC doesn't exist in the path (yet), prepend it
	export PATH="$NDKTC/bin:$PATH"
fi

# Set some common makefile references
export AS=${CROSS_COMPILE}as
export AR=${CROSS_COMPILE}ar
export CC=${CROSS_COMPILE}gcc
export CXX=${CROSS_COMPILE}g++
export CPP=${CROSS_COMPILE}cpp
export LD=${CROSS_COMPILE}ld
export NM=${CROSS_COMPILE}nm
export OBJCOPY=${CROSS_COMPILE}objcopy
export OBJDUMP=${CROSS_COMPILE}objdump
export READELF=${CROSS_COMPILE}readelf
export RANLIB=${CROSS_COMPILE}ranlib
export SIZE=${CROSS_COMPILE}size
export STRINGS=${CROSS_COMPILE}strings
export STRIP=${CROSS_COMPILE}strip

if [[ "$TCOVERRIDE" -eq 1 ]]; then # This is not a a good idea...
	alias as="$AS"
	alias ar="$AR"
	alias gcc="$CC"
	alias g++="$CXX"
	alias cpp="$CPP"
	alias ld="$LD"
	alias nm="$NM"
	alias objcopy="$OBJCOPY"
	alias objdump="$OBJDUMP"
	alias readelf="$READELF"
	alias ranlib="$RANLIB"
	alias size="$SIZE"
	alias strings="$STRINGS"
	alias strip="$STRIP"
fi

export CONFIGANDROID="$CONFIGANDROID"
export CC2="$CC -fPIC -fPIE -pie"
export CCC="$CC $CFLAGS $LDFLAGS"
export CXX="$CXX $CXXFLAGS $LDFLAGS"
export SSTRIP="$STRIP $STRIPFLAGS"

echo "Done setting your environment"
echo
echo "CFLAGS: $CFLAGS"
echo "LDFLAGS: $LDFLAGS"
echo "CC points to $CC and this points to $(which "$CC")"
echo
echo "Use \"\$CC\" command for calling gcc and \"\$CCC\" command for calling our optimized CC"
echo "Use \"\$CXX\" command for calling g++ and \"\$CCXX\" for calling our optimized CXX"
echo "Use \"\$STRIP\" command for calling strip and \"\$SSTRIP\" command for calling our optimized STRIP"
echo
echo "Example: \"\$CCC myprogram.c -o mybinary && \$SSTRIP mybinary \""
echo
echo "When using makefiles with configure options, always use \"./configure \$CONFIGANDROID\" instead of using \"./configure\" itself"
echo "Please notice that makefiles may, or may not, borrow our CFLAGS and LFLAGS, so I suggest to double-check them and eventually append them to makefile itself"
echo "Pro tip: Makefiles with configure options always borrow CC, CFLAGS and LDFLAGS, so if you're using ./configure, probably you don't need to do anything else"
