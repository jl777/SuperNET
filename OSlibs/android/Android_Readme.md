## Quick Android Environment setup instructions

- Download NDK command line toolkit from http://developer.android.com/ndk/downloads/index.html
- Extract the archive or execute the binary to extract the files.
- Rename the extracted directory to "ndk"
- cd ndk
- Execute following command to create a standalone NDK Toolchain, which will be used to compile iguana for Android. MAKE SURE TO CHANGE VALUE OF "--install-dir".

`build/tools/make-standalone-toolchain.sh --toolchain=arm-linux-androideabi-4.9 --platform=android-21 --install-dir=/home/user/ndkTC`

- Copy "curl" and "openssl" directory from "/android/include/" to NDK Standalone Toolchain directory's library includes directory. (eg. /home/user/ndkTC/sysroot/usr/include/)
- Copy all files from "/android/lib/" to NDK Standalone Toolchain directory's "lib" files directory. (eg. /home/user/ndkTC/sysroot/usr/lib/)

- Now edit the "set_android_env.sh" file's 'BASIC' section with correct path of 'NDK' and 'NDKTC'.
- Make sure "set_android_env.sh" file is executable. set it to executable with command 'chmod 755 set_android_env.sh'

- Once done execute the 'set_android_env.sh' to set the Android Development Environment for that terminal window using following command:

source set_android_env.sh

- Check if you get output of following commands:

`echo $CC`

`echo $CC2`

`echo $AR`

- If getting output your Android NDK developement environment is set temporarily in terminal window in which you executed the set_android_env.sh script.


## Compile iguana for android

- Once you have the Android NDK environment set, execute the following commands:

`./m_onetime_android`

`./m_android`


NOTE: This build of iguan will only work with Android version 5.x. Tested with Android 6.0 gave errors related to libssl functions. If you want to compile iguana for Android 6.0, you either need to compile static 'libssl.a' or NDK 'Platform 23' directory.

More detailed instructions you may visit the developer wiki at https://phabricator.supernet.org/w/iguana/development/android/