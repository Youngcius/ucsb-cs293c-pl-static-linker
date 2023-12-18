#!/bin/bash

# use our linker
python ../../main.py multvec.o addvec.o -a libvec.a


# use GNU
ar rcs libvec-gnu.a addvec.o multvec.o 
