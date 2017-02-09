REQUIRED_BINARY_LINKER_ARGS="--no-dynamic-linker"

if [[ $CXX_COMPILER == "true" ]] && [[ -f "$BUILD_ABS/sysroot_vmapp/x86_64-vmapp-elf/lib/libc++.so.1.0" ]]; then
    REQUIRED_BINARY_LINKER_ARGS="$REQUIRED_LINKER_ARGS -lc++ -lpthread -lbfunwind"
fi

if [[ -f "$BUILD_ABS/sysroot_vmapp/x86_64-vmapp-elf/lib/libc.so" ]]; then
    REQUIRED_BINARY_LINKER_ARGS="$REQUIRED_BINARY_LINKER_ARGS -lc"
fi

if [[ -f "$BUILD_ABS/sysroot_vmapp/x86_64-vmapp-elf/lib/cross/libbfsyscall.so" ]]; then
    REQUIRED_BINARY_LINKER_ARGS="$REQUIRED_BINARY_LINKER_ARGS -lbfsyscall"
fi

if [[ -f "$BUILD_ABS/sysroot_vmapp/x86_64-vmapp-elf/lib/cross/libbfcrt_static.a" ]]; then
    REQUIRED_BINARY_LINKER_ARGS="$REQUIRED_BINARY_LINKER_ARGS --whole-archive -lbfcrt_static"
fi

if [[ ! $SHARED_LIBRARY == "true" ]]; then
    REQUIRED_LINKER_ARGS="$REQUIRED_LINKER_ARGS $REQUIRED_BINARY_LINKER_ARGS"
fi

# ------------------------------------------------------------------------------
# Custom Variables
# ------------------------------------------------------------------------------

# %CUSTOM_VARIABLES%
