CC	= g++
CFLAGS	= -g
PROYECT = defensa

.PHONY: all 


all: 
	$(CC) $(CFLAGS) -o $(PROYECT) utils.c ptrace.c defensa.cpp


clean:
	rm -f $(PROYECT)
