FILE=attack

EXEC=$(FILE)

CC_OPTS=-std=c++11 -c -pipe -Wno-switch  -g3 -O3 -fopenmp
LN_OPTS=-std=c++11 
CC=g++

all:Build

OBJ = $(FILE).o


$(FILE).o : $(FILE).cpp
	$(CC) $(CC_OPTS) -o $(FILE).o $(FILE).cpp

   
Build : $(OBJ) Makefile
	$(CC) $(LN_OPTS) -o $(EXEC) $(OBJ) -lcrypto -fopenmp 


clean:
	rm -f $(B_DIR)/* 
