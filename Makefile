CC	= gcc
CFLAGS	= -g
PROYECT = uaf_defense

.PHONY: all 


all: 
	$(CC) $(CFLAGS) -o $(PROYECT) defensa.c


clean:
	rm -f $(PROYECT)
