#!/bin/bash

# use our linker
python ../../main.py start.o main.o sum.o -e main.out
objdump -d main.out > main.txt
./main.out
echo "Result via our linker: $?"
echo ""

# use GNU
# gcc -o main-gnu.out main.o sum.o
ld -o main-gnu.out start.o main.o sum.o
objdump -d main-gnu.out > main-gnu.txt
./main-gnu.out
echo "Result via GNU: $?"
echo ""
