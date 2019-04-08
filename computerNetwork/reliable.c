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
int is_EOF(packet_t* packet);
int is_ACK(packet_t* packet);

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

    int ENV_ACK;

//    use a EOF_ERR_FLAG to mark the read of eof or err from the sender side
    int EOF_ERR_FLAG;
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
    //begining ackno = 1
    r->ENV_ACK = 1;
    //EOF-ERR-FLAG
    r->EOF_ERR_FLAG = 0;

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
    //we first check if the packet is corrupted or not. If so, discard this packet（namely, do nothing）
    uint16_t packet_length = ntohs(pkt->len);
    uint16_t packet_cksum = ntohs(pkt->cksum);
    uint16_t packet_seqno = ntohl(pkt->seqno);
    if((packet_length != (uint16_t) n) || (packet_cksum != ntohs(cksum(pkt->data, (int) packet_length)))){
        fprintf(stderr, "packet corrupted!\n");
//        return NULL;
    }

    //distinguish ACK. (EOF. Data)
    if (is_ACK(pkt)){
        //if the received packet is ack, then we remove (ack) all packet with seqno number < ackno in the send buffer
        int acked_packet_number = buffer_remove(r->send_buffer, ntohl(pkt->ackno));
        //set up the sliding window
        //TODO double check this one, not sure should be ackno-1 or ackno
        r->SND_UNA = (int) ntohl(pkt->ackno);
        fprintf(stderr, "removed acked packets : %d", acked_packet_number);
        //since sliding window moved now, we can read more data if there is any
        rel_read(r);
//        return NULL;
    }else{//EOF and normal data packets are both data packets, share some commonality,
//        Thus we handle them together
//        If the received data packet(including EOF and Data) were not acked, we push it into the receiver buffer
//        Otherwise we simply ack again(maybe the ack packet got lost in the network)
        if(packet_seqno >= r->RCV_NXT){
//            we push packet into the receive buffer(if there is space in the window)
//            since the buffer_insert method will place the packet with the order of pac->seqno.
//            we only need to check if the buffer size w.r.t MAXWND
            int MAXWND = r->MAXWND;

            if(buffer_size(r->rec_buffer) < (uint32_t) MAXWND ){
//              we still got space in the receive window
                buffer_insert(r->rec_buffer, pkt, get_current_system_time());

//              OK now we plug this packet into the buffer
//              let's flush all in order packets in the receiving buffer into output
//              until we reached an insuccesive one.
                buffer_node_t* first_node = buffer_get_first(r->rec_buffer);
                packet_t* packet = &(first_node->packet);
                while((ntohl(packet->seqno) == (uint32_t) r->RCV_NXT) && (first_node != NULL)){
                    if(is_EOF(packet)){
                        //If we reached the EOF, we tell the conn_output and destroy the connection
                        conn_output(r->c, packet->data, 0); //send a signal to output by calling conn_output with len 0
                        //send an ackno to the sender side

                        struct ack_packet* ack_pac = xmalloc(sizeof(struct ack_packet));
                        ack_pac->ackno = htonl((uint32_t) (packet_seqno + 1));
                        ack_pac->len = htons ((uint16_t) 8);
                        ack_pac->cksum = (uint16_t) 0;
                        ack_pac->cksum = cksum(ack_pac, (int) 8);

                        conn_sendpkt(r->c, (packet_t *)ack_pac, (size_t) 8);
                        free(ack_pac);

                        //destroy the connection
                        if(r->EOF_ERR_FLAG == 1){
                            rel_destroy(r);
                        }

                    }else{
                        //flush the normal data to the output
                        while(conn_bufspace(r->c) < (packet->len)){
                            //spin
                        }

                        int bytes_flushed = conn_output(r->c, packet->data, (size_t) (packet_length - 12));
                        fprintf(stderr, "bytes_flushed : %d", bytes_flushed);

                        struct ack_packet* ack_pac = xmalloc(sizeof(struct ack_packet));
                        ack_pac->ackno = htonl((uint32_t) (packet_seqno + 1));
                        ack_pac->len = htons ((uint16_t) 8);
                        ack_pac->cksum = (uint16_t) 0;
                        ack_pac->cksum = cksum(ack_pac, (int) 8);

                        conn_sendpkt(r->c, (packet_t *)ack_pac, (size_t) 8);
                        free(ack_pac);

                    }

                    buffer_remove_first(r->rec_buffer); //remove either EOF or Data packet whatever
                    r->RCV_NXT ++;
                    first_node = buffer_get_first(r->rec_buffer);
                    packet = &(first_node->packet);
                }


            }else{//no space in the receive buffer. return without doing anything
                return;
            }


        }else{ //packet_seqno < r->RCV_NXT
//            make an ack packet with ackno = seqno + 1 and send it.
            struct ack_packet* ack_pac = xmalloc(sizeof(struct ack_packet));
            ack_pac->ackno = htonl((uint32_t) (packet_seqno + 1));
            ack_pac->len = htons ((uint16_t) 8);
            ack_pac->cksum = (uint16_t) 0;
            ack_pac->cksum = cksum(ack_pac, (int) 8);

            conn_sendpkt(r->c, (packet_t *)ack_pac, (size_t) 8);
            free(ack_pac);
        }




    }


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
        int read_byte = conn_input(s->c, packet->data, 500);
        if (read_byte == -1) {
            //we have received an EOF signal. Create an EOF packet and Mark it with the Flag
            s->EOF_ERR_FLAG = 1;
            //which has "zero length payload", and we should also push this packet in the buffer
            //        packet->data = ()0;
            packet->len = htons((uint16_t) 12);
            packet->ackno = htonl((uint32_t) 0); //EOF packet, ackno doesn't matter
            packet->seqno = htonl((uint32_t) SND_NXT);
            //moving the sliding window
            s->SND_NXT = s->SND_NXT + 1;

            packet->cksum = (uint16_t) 0;
            packet->cksum = cksum(packet, 12);

            //finished packing the EOF packek, push it into the send buffer
            buffer_insert(s->send_buffer, packet, get_current_system_time());
            conn_sendpkt(s->c, packet, (size_t) 12);
            free(packet);

        } else if (read_byte == 0) {
            free(packet);
//            return NULL; // the lib will call rel_read again on its own
        } else {
            packet->len = htons((uint16_t)(12 + read_byte));
            packet->ackno = htonl((uint32_t) 0); //data packet, ackno doesn't matter
            packet->cksum = htons((uint16_t) 0);
            packet->seqno = htonl((uint32_t) SND_NXT);
            //moving the sliding window
            s->SND_NXT = s->SND_NXT + 1;

            packet->cksum = (uint16_t) 0;
            packet->cksum = cksum(packet, 12 + read_byte);

            //finished packing the data packek, push it into the send buffer
            buffer_insert(s->send_buffer, packet, get_current_system_time());
            conn_sendpkt(s->c, packet, (size_t) 12 + read_byte);
            free(packet);
        }

    }
//    return NULL;
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

int is_EOF(packet_t* packet){
    if(packet->len == (uint16_t) 12){
        return 1;
    }else{
        return 0;
    }
}

int is_ACK(packet_t* packet){
    if(packet->len == (uint16_t) 8){
        return 1;
    }else{
        return 0;
    }
}