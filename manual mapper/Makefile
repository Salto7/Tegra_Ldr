# Makefile for ManualDLLMapper

CC = x86_64-w64-mingw32-gcc
CFLAGS_dll = -Wall -Wextra  -DUNICODE -D_UNICODE -O0 -shared -IIncludes
CFLAGS_exe = -Wall -Wextra  -DUNICODE -D_UNICODE -Os  -IIncludes
TARGET = Tegra_ldr
SRC = src/*.c

all: $(TARGET)

exe: $(SRC)
	$(CC) $(CFLAGS_exe) -o Bin/$(TARGET).exe $(SRC) 

dll: $(SRC)
	$(CC) $(CFLAGS_dll) -o Bin/$(TARGET).dll $(SRC)
clean:
	rm -f  ./*.dll
	rm -f  ./*.exe
