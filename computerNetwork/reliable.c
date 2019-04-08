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

/*
 * ack pack length = 8
 * eof pack length = 12
 * header length = 12
 * packet max size = 512
 * data max length = 500
 */
long get_current_system_time();

struct reliable_state {
    rel_t *next;			/* Linked list for traversing all connections */
    rel_t **prev;

    conn_t *c;			/* This is the connection object */

    /* Add your own data fields below this */
    buffer_t* send_buffer;
    buffer_t* rec_buffer;
/*    For the sender side sliding window we need to maintain:
 *     1.SND.UNA    lowest seqno of outstanding frames, SND.UNA = max(SND.UNA, ackno) when an ACK arrives
 *     2.SND.NXT    seqno of next frame to send out, should be equals to the latest sent pack's seqno + 1
 *     3.SND.MAXWIND  max window size
 *     4.Timeout    don't know how to do this one... associate timeouts wih each frame sent retransmit if no ACK
 *                  reeived before timeout
 *
 *       relevant state but can be calculated: SND.WND = SND.NXT - SND.UNA, SND.WND varies from time!
 *       and SND.WND <= MAXWND
 */
    int SND_UNA; int SND_NXT; int MAXWND; int timeout;

/*    For the receiver side sliding window we need to maintain:
 *      1.RCV.NXT   next seqno expected
 *      2.RCV.WND   == MAXWND
 *          if receiving pac has seqno >= RCV.NXT + RCV.WND: then drop this pac
 *          else:                                            store in the rev. buffer
 *
 *          if seqno == RCV.NXT: a. set RCV.NXT to the highest seqno consecutively stored in the buffer + 1
 *                               b. flush data [seqno, RCV.NXT - 1] to out
 *                               c. send back ACK with cumulative ackno = RCV.NXT
 */
    int RCV_NXT; int RCV_WND;
};
rel_t *rel_list;

/* Creates a new reliable protocol session, returns NULL on failure.
* ss is always NULL */
rel_t *
rel_create (conn_t *c, const struct sockaddr_storage *ss,
const struct config_common *cc)
{
    rel_t *r;

    r = xmalloc (sizeof (*r));
    memset (r, 0, sizeof (*r));

    if (!c) {
        c = conn_create (r, ss);
        if (!c) {
            free (r);
            return NULL;
        }
    }

    r->c = c;
    r->next = rel_list;
    r->prev = &rel_list;
    if (rel_list)
    rel_list->prev = &r->next;
    rel_list = r;

    /* Do any other initialization you need here... */
    // initialize the buffers
    r->send_buffer = xmalloc(sizeof(buffer_t));
    r->send_buffer->head = NULL;
    r->rec_buffer = xmalloc(sizeof(buffer_t));
    r->rec_buffer->head = NULL;
    //set SND.UNA, SND.NXT, RCV.NXT = 0
    r->SND_UNA = r->SND_NXT = r->RCV_NXT = 0;
    //read max window size from the configuration parameters via the command
    r->MAXWND = cc->window;
    //read timeout from the configuration parameters passed via the command
    r->timeout = cc->timeout;

    return r;
}

void
rel_destroy (rel_t *r)
{
    if (r->next) {
        r->next->prev = r->prev;
    }
    *r->prev = r->next;
    conn_destroy (r->c);

    /* Free any other allocated memory here */
    buffer_clear(r->send_buffer);
    free(r->send_buffer);
    buffer_clear(r->rec_buffer);
    free(r->rec_buffer);
    // ...

}

// n is the expected length of pkt
void
rel_recvpkt (rel_t *r, packet_t *pkt, size_t n)
{
    //TODO can reiceive ack, eof or data , need to distinguish them
}

void
rel_read (rel_t *s)
{
    /*First we need to check if there is still space in sender sliding window buffer*/
    //
    int SND_UNA = s->SND_UNA;
    int SND_NXT = s->SND_NXT;
    int MAXWND = s->MAXWND;
    if(SND_NXT - SND_UNA < MAXWND) {
        //there is still space in the sliding window
        //allocate space for a packet
        packet_t *packet = (packet_t *) xmalloc(512);
        //read from conn_input, it returns the number of bytes
        // 0 if there is no data currently available, and -1 on EOF or error.
        int read_byte = conn_input(r->c, packet->data, 500);
        if (read_byte == -1) {
            //we have received an EOF signal. Create an EOF packet
            //which has "zero length payload", and we should also push this packet in the buffer
            //        packet->data = ()0;
            packet->len = htons((uint16_t) 12);
            packet->ackno = htonl((uint32_t) 0); //EOF packet, ackno doesn't matter
            packet->seqno = htonl((uint32_t) SND_NXT);
            //moving the sliding window
            s->SND_NXT = s->SND_NXT + 1;

            packet->cksum = (uint16_t) 0;
            packet->cksum = cksum(packet->data, packet->len);

            //finished packing the EOF packek, push it into the send buffer
            buffer_insert(s->send_buffer, packet, get_current_system_time());
            conn_sendpkt(s->c, packet, (size_t) 12);
            free(packet);

        } else if (read_byte == 0) {
            free(packet);
            return NULL; // the lib will call rel_read again on its own
        } else {
            packet->len = htons((uint16_t)(12 + read_byte));
            packet->ackno = htonl((uint32_t) 0); //data packet, ackno doesn't matter
            packet->cksum = htons((uint16_t) 0);
            packet->seqno = htonl((uint32_t) SND_NXT);
            //moving the sliding window
            s->SND_NXT = s->SND_NXT + 1;

            packet->cksum = (uint16_t) 0;
            packet->cksum = cksum(packet->data, packet->len);

            //finished packing the data packek, push it into the send buffer
            buffer_insert(s->send_buffer, packet, get_current_system_time());
            conn_sendpkt(s->c, packet, (size_t) 12 + read_byte);
            free(packet);
        }

    }
    return NULL;
}

void
rel_output (rel_t *r)
{
    /* Your logic implementation here */
}

void
rel_timer ()
{
    // Go over all reliable senders, and have them send out
    // all packets whose timer has expired
    rel_t *current = rel_list;
    while (current != NULL) {
        // ...
        current = rel_list->next;
    }
}

long get_current_system_time()
{ // now in milliseconds
    struct timeval now;
    gettimeofday(&now, NULL);
    long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
    return now_ms;
}
