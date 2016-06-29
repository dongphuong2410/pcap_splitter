//  Hello World server

#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>

#define MB 1024*1024

int main (int argc, char **argv)
{
	uint64_t recv_bytes = 0;
    //  Socket to talk to clients
    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);
    char *read_buf = malloc(sizeof(char) * MB);

    char zmq_socket_name[50];
    sprintf(zmq_socket_name, "ipc:///tmp/pcap_zmq%d", atoi(argv[1]));
    char ipc_num = atoi(argv[1]);
    int rc = zmq_bind (responder, zmq_socket_name);
    assert (rc == 0);
    printf("zmq_bind : %s\n", zmq_socket_name);
    zmq_msg_t msg;
    zmq_msg_init_data(&msg, read_buf, sizeof(char) * MB, NULL, NULL);

    while (1) {
	int size = zmq_msg_recv(&msg, responder, 0);
	recv_bytes += size;
	printf("zmq_msg_recv : %d, %"PRIu64"\n", size, recv_bytes);
	usleep(10000);
        zmq_send (responder, &ipc_num, 1, 0);
    }
    return 0;
}
