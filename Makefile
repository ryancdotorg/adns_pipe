HEADERS = adns_pipe.h
OBJECTS = adns_pipe.o
LIBS = -lcares

CC=gcc
CFLAGS=-O2 -g -Wall -std=gnu99 -pedantic -Wall -Wextra

.o:
	$(CC) $(CFLAGS) -c $< -o $@

adns_pipe: $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LIBS) -o adns_pipe

ec2.sh.gz: adns_pipe gen_ec2_user_data.sh
	./gen_ec2_user_data.sh

ec2: ec2.sh.gz

all: adns_pipe


clean:
	rm -rf adns_pipe ec2.sh.gz *.o
