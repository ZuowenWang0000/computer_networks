#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "rlib.h"
#include "buffer.h"


int main(){
    int a,b,c;

    a = b = c = 0;

//    printf("a = b = c = %d", a);

    packet_t *pac;
    pac = malloc(sizeof(*pac));
    printf("%d\n", sizeof(pac));
    printf("%d\n",sizeof(* pac));
    printf("%d\n",sizeof(packet_t *));

    printf("%d'n", (int) 3 < (uint16_t) 2);

    return 0;
}