#ZMQ_CFLAGS=$(pkg-config --libs --cflags libczmq libzmq)
ZMQ_CFLAGS=$(pkg-config --libs --cflags libzmq)
PCAP_CFLAGS=-lpcap

INCLUDES=./uthash

SRC=main.c \
    mempool.c

TARGET=pcap_sender

all:
	gcc -g -D_GNU_SOURCE -Wall $(SRC) pcap_idx_lib.a -I$(INCLUDES) -o $(TARGET) -lzmq -lpcap -lpthread

clean:
	rm -rf $(TARGET)
