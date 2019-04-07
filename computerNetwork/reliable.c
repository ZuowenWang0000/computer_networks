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
    // ...
    r->send_buffer = xmalloc(sizeof(buffer_t));
    r->send_buffer->head = NULL;
    // ...
    r->rec_buffer = xmalloc(sizeof(buffer_t));
    r->rec_buffer->head = NULL;
    // ...
    //set SND.UNA, SND.NXT, RCV.NXT = 0
    r->SND_UNA = r->SND_NXT = r->RCV_NXT = 0;
    //read max window size from the configuration parameters via the command
    r->MAXWND = cc->window
    //read timeout from the configuration parameters passed via the command
    r->timeout = cc->timeout

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
    /* Your logic implementation here */
}

void
rel_read (rel_t *s)
{
    /* Your logic implementation here */
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
