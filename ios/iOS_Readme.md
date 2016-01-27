## Quick iOS Development Environment setup instructions

- Install xcode from Apple App Store.
- Execute command `xcode-select --install` from Terminal. Install Command line tools
- Install Git for command line. Get installer from here: http://git-scm.com/download/mac

## Compile iguana for iOS

- Get SuperNET repository clonned on your machine with command

`git clone https://github.com/jl777/SuperNET`

- Change your directory to the clonned SuperNET and execute the following commands:

`./m_onetime m_ios`

`./m_ios`

- You'll find `libcrypto777.a` and `iguana` for iOS in agents directory inside SuperNET repo clonned dir.
- To check if the files are for iOS platform, you can execute the folowing command which will show a result something like this:

`cd agents`

`lipo -info iguana`

Expected result:

`Architectures in the fat file: agents/iguana are: armv7 armv7s arm64`


## Info on iOS libraries ##
The iOS libraries libcrypto.a, libssl.a, and libcurl.a are picked from the following github repositories:
https://github.com/sinofool/build-libcurl-ios
https://github.com/sinofool/build-libcurl-ios


NOTE: This build of iguana iOS has not been tested with any iOS device due to the limitations of iOS App has to execute system commands in iOS devices. A task is created in developer channel to help testing this iguana iOS compile. Please head over to this link for more detail: https://phabricator.supernet.org/T398

More detailed instructions you may visit the developer wiki at https://phabricator.supernet.org/w/iguana/development/ios/
