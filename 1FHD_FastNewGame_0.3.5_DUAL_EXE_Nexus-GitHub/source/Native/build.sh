#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
gcc -m32 -std=c11 -O2 -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -fno-pic -fno-pie -c fast_new_game.c -o fast_new_game.o
python3 elf_to_coff.py fast_new_game.o fast_new_game.coff
ld -m i386pe --no-leading-underscore --shared --entry DllMain@12 --subsystem windows --image-base 0x13400000 --disable-auto-import --no-insert-timestamp fast_new_game.coff fast_new_game.def -o ../../Native/FHD_FastNewGame.XenoPlugin.dll
rm -f fast_new_game.o fast_new_game.coff
