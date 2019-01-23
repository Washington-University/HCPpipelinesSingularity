#!/bin/sh

##############################################################################

# check-libglvnd-install.sh

# Checks for an existing libglvnd installation. A driver installer can use this
# to determine whether or not it needs to install its own copies of the
# libraries.

# Usage: check-libglvnd-install.sh [HELPER_DIRECTORY]
# The optional HELPER_DIRECTORY argument is the directory with the various
# helper programs and libraries used by the script. If unspecified, it will
# look in the same directory as the script itself.

# The script will exit with one of these values:
# 0 -- All libglvnd libraries are installed and working.
# 1 -- No libglvnd libraries are installed.
# 2 -- Some of the libraries are installed, but some are missing.
# 3 -- Some internal error occurred.

##############################################################################

# Exit codes.
RESULT_INSTALLED=0
RESULT_NOT_INSTALLED=1
RESULT_PARTIAL=2
RESULT_ERROR=3

# The exit codes used in the test programs.
TEST_RESULT_SUCCESS=0
TEST_RESULT_USER_ERROR=1
TEST_RESULT_LIBRARY_NOT_FOUND=2
TEST_RESULT_VERSION_MISMATCH=3
TEST_RESULT_INTERNAL_ERROR=4

# Lists of found and missing libraries to report
FOUND_LIBRARIES=
MISSING_LIBRARIES=

# Find the directory with the help binaries. If it isn't given on the
# command-line, then try the current directory.
TEST_PROGRAM_BASE=$1
if [ "x$TEST_PROGRAM_BASE" = "x" ] ; then
    TEST_PROGRAM_BASE=`dirname $0`
fi
cd $TEST_PROGRAM_BASE || exit $RESULT_ERROR
TEST_PROGRAM_BASE=`pwd`

echo Checking for libglvnd installation.

# Make sure all the helper programs and libraries exist.
for PROG in check-entrypoint check-libgldispatch ; do
    if [ ! -x $TEST_PROGRAM_BASE/$PROG ] ; then
        echo Missing test program: $TEST_PROGRAM_BASE/$PROG
        exit $RESULT_ERROR
    fi
done

# Check if we have the helper programs for GLX.
SHOULD_CHECK_GLX=0
if [ -x $TEST_PROGRAM_BASE/check-libglx ] ; then
    SHOULD_CHECK_GLX=1
    if [ ! -f $TEST_PROGRAM_BASE/libGLX_installertest.so.0 ] ; then
        echo Missing test library: $TEST_PROGRAM_BASE/libGLX_installertest.so.0
        exit $RESULT_ERROR
    fi
fi

# Check if we have the helper programs for EGL.
SHOULD_CHECK_EGL=0
if [ -x $TEST_PROGRAM_BASE/check-libegl ] ; then
    SHOULD_CHECK_EGL=1

    # Make sure we've got the other files, too.
    if [ ! -f $TEST_PROGRAM_BASE/egl_installertest.json ] ; then
        echo Missing test file: $TEST_PROGRAM_BASE/egl_installertest.json
        exit $RESULT_ERROR
    fi
    if [ ! -f $TEST_PROGRAM_BASE/libEGL_installertest.so.0 ] ; then
        echo Missing test library: $TEST_PROGRAM_BASE/libEGL_installertest.so.0
        exit $RESULT_ERROR
    fi
fi

# Check for libGLdispatch first. If that's not available, then nothing else
# will work.
echo Checking libGLdispatch...
$TEST_PROGRAM_BASE/check-libgldispatch libGLdispatch.so.0
RET=$?
if [ "$RET" -eq $TEST_RESULT_LIBRARY_NOT_FOUND ] ; then
    exit $RESULT_NOT_INSTALLED
elif [ "$RET" -ne $TEST_RESULT_SUCCESS ] ; then
    exit $RESULT_NOT_INSTALLED
fi

echo Checking libGLdispatch dispatch table
$TEST_PROGRAM_BASE/check-entrypoint libGLdispatch.so.0
if [ $? -ne $TEST_RESULT_SUCCESS ] ; then
    exit $RESULT_NOT_INSTALLED
fi

FOUND_LIBRARIES="libGLdispatch.so.0 $FOUND_LIBRARIES"
echo libGLdispatch is OK

# Check if libGLX is installed. This works by forcing it to load a dummy vendor
# library.
if [ "$SHOULD_CHECK_GLX" -eq 1 ] ; then
    echo Checking for libGLX
    OLD_LIBRARY_PATH=$LD_LIBRARY_PATH
    export LD_LIBRARY_PATH="$TEST_PROGRAM_BASE:$LD_LIBRARY_PATH"
    export __GLX_VENDOR_LIBRARY_NAME=installertest
    if $TEST_PROGRAM_BASE/check-libglx $TEST_PROGRAM_BASE/libGLX_installertest.so.0 libGLX.so.0 ; then
        unset __GLX_VENDOR_LIBRARY_NAME
        export LD_LIBRARY_PATH="$OLD_LIBRARY_PATH"
        FOUND_LIBRARIES="libGLX.so.0 $FOUND_LIBRARIES"
        echo libGLX is OK
    else
        MISSING_LIBRARIES="libGLX.so.0 $MISSING_LIBRARIES"
    fi
fi

if [ "$SHOULD_CHECK_EGL" -eq 1 ] ; then
    echo Checking for libEGL
    OLD_LIBRARY_PATH=$LD_LIBRARY_PATH
    export LD_LIBRARY_PATH=$TEST_PROGRAM_BASE:$LD_LIBRARY_PATH
    export __EGL_VENDOR_LIBRARY_FILENAMES=$TEST_PROGRAM_BASE/egl_installertest.json
    if $TEST_PROGRAM_BASE/check-libegl libEGL.so.1 ; then
        unset __EGL_VENDOR_LIBRARY_FILENAMES
        export LD_LIBRARY_PATH=$OLD_LIBRARY_PATH
        FOUND_LIBRARIES="libEGL.so.1 $FOUND_LIBRARIES"
        echo libEGL is OK
    else
        MISSING_LIBRARIES="libEGL.so.1 $MISSING_LIBRARIES"
    fi
fi

# Check each of the entrypoint libraries.
for ENTRYPOINT_LIB in libOpenGL.so.0 libGL.so.1 ; do
    echo Checking entrypoint library $ENTRYPOINT_LIB
    if $TEST_PROGRAM_BASE/check-entrypoint libGLdispatch.so.0 $ENTRYPOINT_LIB ; then
        FOUND_LIBRARIES="$ENTRYPOINT_LIB $FOUND_LIBRARIES"
        echo Entrypoint library $ENTRYPOINT_LIB is OK
    else
        MISSING_LIBRARIES="$ENTRYPOINT_LIB $MISSING_LIBRARIES"
    fi
done

# Report lists of found and missing libraries. Do not change the text of the
# "{Found,Missing} libglvnd libraries: " banners, as these may be parsed out
# of the output of this script by its caller.
echo
echo "Found libglvnd libraries: $FOUND_LIBRARIES"
echo "Missing libglvnd libraries: $MISSING_LIBRARIES"
echo

# Report overall status of GLVND installation in this script's exit code.
if [ -z "$MISSING_LIBRARIES" ]; then
    # Everything appears to be installed and working correctly.
    echo libglvnd appears to be installed.
    exit $RESULT_INSTALLED
elif [ -z "$FOUND_LIBRARIES" ]; then
    # It shouldn't be possible for this script to reach this far without
    # having found at least libGLdispatch, but handle this case anyway.
    exit $RESULT_NOT_INSTALLED
else
    # At least one, but not quite all, of the GLVND libraries are missing
    exit $RESULT_PARTIAL
fi
