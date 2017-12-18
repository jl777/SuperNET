#!/bin/sh

TMP_DIR=~/tmp/iguana

# make a tmp directory
mkdir -p $TMP_DIR
echo "making $TMP_DIR"

binaries=("iguana" "marketmaker")

for binary in "${binaries[@]}";
do
    echo "copying $binary to $TMP_DIR"

    if [ "$binary" = "iguana" ]
        then
        cp agents/$binary $TMP_DIR
    fi

    if [ "$binary" = "marketmaker" ]
        then
        cp iguana/$binary $TMP_DIR
    fi

    # find the dylibs to copy for iguana
    DYLIBS=`otool -L $TMP_DIR/$binary | grep "/usr/local" | awk -F' ' '{ print $1 }'`
    echo "copying $DYLIBS to $TMP_DIR"

    # copy the dylibs to the tmpdir
    for dylib in $DYLIBS; do cp -rf $dylib $TMP_DIR/; done

    # modify iguana to point to dylibs
    echo "modifying $binary to use local libraries"
    for dylib in $DYLIBS; do install_name_tool -change $dylib @executable_path/`basename $dylib` $TMP_DIR/$binary; done;
done
