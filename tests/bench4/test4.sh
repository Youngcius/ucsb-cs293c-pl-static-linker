#!/bin/bash

# use our linker
python ../../main.py multvec.o addvec.o -so libvec.so
# echo "Result via our linker:"
# ./main.out
echo ""

# use GNU
gcc -shared -fpic -o libvec.so addvec.c multvec.c
# echo "Result via GNU:"
echo ""
