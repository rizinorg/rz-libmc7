# Rizin MC7 disassembler 

Library to disassemble MC7 bytecode for Siemens PLC SIMATIC S7-300 and S7-400

**please report any bug. this is experimental for now**

## Install

```bash
meson build
ninja -C build
sudo ninja -C build install
```

## Usage

```
$ rizin sample.mc7.bin
[0x00000000]> e asm.arch = mc7
[0x00000000]> pdi 5 @ 0x24
0x00000024                 600d  +D
0x00000026                 6009  -D
0x00000028                 600a  *D
0x0000002a                 600e  /D
0x0000002c                 6001  MOD
```
