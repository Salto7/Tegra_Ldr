ProjectName		= trampolineShellcode

CCX64			= x86_64-w64-mingw32-gcc

CFLAGS			=  -O0 -fno-asynchronous-unwind-tables -nostdlib
CFLAGS 			+= -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  		+= -s -ffunction-sections -falign-jumps=1 -w
CFLAGS			+= -falign-labels=1 -fPIC -Wl,-TScripts/linker.ld
CFLAGS			+= -Wl,-s,--no-seh,--enable-stdcall-fixup 
CFLAGS			+= -fomit-frame-pointer

EXECUTABLE_X64	= Bin/$(ProjectName).x64.exe
RAWBINARY_X64	= Bin/$(ProjectName).x64.bin

all: x64 

x64: clean
	@ echo "[*] Compile x64 executable..."
	
	@ nasm  -f win64 src/asm_aligner.asm -o Bin/asm_aligner.o
	 
	@ $(CCX64) src/*.c Bin/asm_aligner.o -o $(EXECUTABLE_X64) $(CFLAGS) $(LFLAGS) -IIncludes -masm=intel

	@ echo "[*] Extract shellcode: $(RAWBINARY_X64)"
	@ python Scripts/extract.py -f $(EXECUTABLE_X64) -o $(RAWBINARY_X64)

	#@ rm $(EXECUTABLE_X64)


clean:
	@ rm -rf Bin/*.o
	@ rm -rf Bin/*.bin
	@ rm -rf Bin/*.exe
