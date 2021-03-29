all: $(EXE1)
	gcc 0x4553_Scorpion.c LDE/0x4553_LDE.s -o 0x4553_Scorpion
	gcc test.c -static -o test -falign-functions=100
	rm output;touch output;chmod +x output
