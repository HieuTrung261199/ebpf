# Manual
    Guide to using bpftrace
# Install
## Install Clang and LLVM
          sudo apt install clang llvm
## Install bpftrace
          sudo apt install bpftrace
# Inspect
          which bpftrace
          which clang
# Test
          sudo bpftrace -e 'BEGIN { printf("bpftrace is working!\n"); }'
