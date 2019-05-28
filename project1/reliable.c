//saturday 1:55

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
int MAX(int a, int b);

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
    int SND_UNA; int SND_NXT; int MAXWND; long timeout;

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

//    int ENV_ACK;

//    use a EOF_ERR_FLAG to mark the read of eof or err from the sender side
    int EOF_ERR_FLAG;

    int EOF_SENT_FLAG;
    int EOF_RECV_FLAG;
    int EOF_ACK_RECV_FLAG;
    int EOF_seqno;
    int flush_busy;

//    FILE *fptr;
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
//TODO  double check SND_UNA should be initialized 0 or 1
    r->SND_UNA = 1;
    r->SND_NXT = 1;
//    r->SND_UNA = 0;
//    r->SND_NXT = 0;



    r->RCV_NXT = 1;
    //read max window size from the configuration parameters via the command
    r->MAXWND = cc->window;
    //read timeout from the configuration parameters passed via the command
    r->timeout = cc->timeout;

//    r->ENV_ACK = 1;
    //EOF-ERR-FLAG
//    r->EOF_ERR_FLAG = 0;

    r->EOF_SENT_FLAG = 0;
    r->EOF_RECV_FLAG = 0;
    r->EOF_ACK_RECV_FLAG = 0;
    r->EOF_seqno = 0;
    r->flush_busy = 0;
//    r->fptr = fopen("./mycodeErrLog.txt", "w");

    return r;
}

void
rel_destroy (rel_t *r)
{
//    fprintf(stderr, "ENTER REL_DESTROY!\n");
//    fsync(2);
//    fsync(1);
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
//    r->EOF_ERR_FLAG = 0;
//    r->SND_UNA = 1;
//    r->SND_NXT = r->RCV_NXT = 1;
    // ...
//    fclose(r->fptr);
//    exit();
}

// n is the expected length of pkt
void
rel_recvpkt (rel_t *r, packet_t *pkt, size_t n)
{

    //we first check if the packet is corrupted or not. If so, discard this packet（namely, do nothing）
    uint16_t packet_length = ntohs(pkt->len);
    uint16_t packet_cksum_old = ntohs(pkt->cksum);
    uint16_t packet_seqno = ntohl(pkt->seqno);

    //need to reset packet checksum to 0 before computing
    uint16_t cksum_old_to_restore = pkt->cksum;
    pkt->cksum = (uint16_t) 0;


    if((packet_length != (uint16_t) n) || (packet_cksum_old != ntohs(cksum(pkt, (int) packet_length)))){
//    if((packet_length < (uint16_t) n) || (packet_cksum_old != ntohs(cksum(pkt, (int) packet_length)))){
//    if((packet_length > (uint16_t) n) || (packet_cksum_old != ntohs(cksum(pkt, (int) packet_length)))){
//        fprintf(r->fptr, "packet_length: %d  ", packet_length);
//        fprintf(r->fptr, "expected length: %d  ", n);
//        fprintf(r->fptr, "packet cksum: %d  ", packet_cksum_old);
//        fprintf(r->fptr, "new cksum: %d  ",ntohs(cksum(pkt, (int) packet_length)));
//        fprintf(r->fptr, "\npacket corrupted!\n");
        return;
    }
    //restore cksum
    pkt->cksum = cksum_old_to_restore;

    //distinguish ACK. (EOF. Data)
    if (is_ACK(pkt)){
//        fprintf(r->fptr, "ACKACKACKACKACK\n\n\n");
        //if the received packet is ack, then we remove (ack) all packet with seqno number < ackno in the send buffer
//        fprintf(r->fptr,"REL_RECVPKT ACK received ackno: %x\n", ntohl(pkt->ackno));
//        fprintf(r->fptr, "REL_RECVPKT ACK  sender buffer size : %x ,  receiver buffer size : %x\n",
//                buffer_size(r->send_buffer),  buffer_size(r->rec_buffer));
        if(pkt->ackno == r->EOF_seqno + 1){
            r->EOF_ACK_RECV_FLAG = 1;
        }



        int acked_packet_number = buffer_remove(r->send_buffer, (uint32_t) ntohl(pkt->ackno));

        fprintf(stderr, "Sender buffer removed acked packets: %x\n", acked_packet_number);
        //set up the sliding window
        //TODO double check this one, not sure should be ackno-1 or ackno
        r->SND_UNA = MAX((int) ntohl(pkt->ackno), r->SND_UNA);
//        fprintf(r->fptr, "\nremoved acked packets : %d\n", acked_packet_number);
        fprintf(stderr, "sender buffer size : %d ,  receiver buffer size : %d\n",
                buffer_size(r->send_buffer),  buffer_size(r->rec_buffer));
        fsync(1); fsync(2);

        //since sliding window moved now, we can read more data if there is an
////        ****************How should I tear down the connection?***********************
//        if(acked_packet_number > 0 && buffer_size(r->send_buffer) == 0){
//            if(r->EOF_ERR_FLAG == 1 && buffer_size(r->rec_buffer) == 0){
//                rel_destroy(r);
//                return;
//            }
//        }
////        ******************************************************************************
        if(r->EOF_RECV_FLAG && r->EOF_SENT_FLAG && r->EOF_ACK_RECV_FLAG && !r->flush_busy && buffer_size(r->send_buffer) == 0){
//            fprintf(stderr, "@@@@@@@@@  DESTROYING!!!!!!!!!!!\n\n\n");
//            fsync(2); fsync(1);
            rel_destroy(r);
            return;
        }
            rel_read(r);


//        return NULL;
    }else{
        //EOF and normal data packets are both data packets, share some commonality,
//        Thus we handle them together
//        If the received data packet(including EOF and Data) were not acked, we push it into the receiver buffer
//        Otherwise we simply ack again(maybe the ack packet got lost in the network)
//        fprintf(r->fptr, "REL_RECVPKT: coming data/eof packet_seqno : %x,   r->RCV_NXT  : %x\n", packet_seqno, r->RCV_NXT);
        if(packet_seqno >= r->RCV_NXT){
            fprintf(stderr, "\nHEREHEREHREHEHREHREHREHEHR\n");

//            if(packet_seqno == r->RCV_NXT){
//                                buffer_insert(r->rec_buffer, pkt, get_current_system_time());
////              OK now we have plug this packet into the buffer
//                if(conn_bufspace(r->c) >= (packet_length - 12)){
////                if(conn_bufspace(r->c) != 0){
//                    rel_output(r);}
//            }


//            we push packet into the receive buffer(if there is space in the window)

            int MAXWND = r->MAXWND;

//            if(buffer_size(r->rec_buffer) >= (uint32_t) MAXWND){
//                fprintf(stderr, "\nHEREHEREHREHEHREHREHREHEHR2222222222222\n");
////                definitely no space, don't even need to check the sliding_window upper bound
//                return;
////  TODO        double check > or >= ?
//            }else
            if(packet_seqno >= r->RCV_NXT + r->MAXWND){
                fprintf(stderr, "\nHEREHEREHREHEHREHREHREHEHR33333333333333\n");
//                if we insert this pac in the buffer, there might be no enough room for the first starting packet(in iterative flush process)
//                thus we also discard it
                return;
            }else{
                fprintf(stderr, "\nHEREHEREHREHEHREHREHREHEHR4444444444444\n");
//              OK now we have plug this packet into the buffer
                if(conn_bufspace(r->c) >= (packet_length - 12)){
                    if(!buffer_contains(r->rec_buffer, ntohl(pkt->seqno))) {
                        buffer_insert(r->rec_buffer, pkt, get_current_system_time());
                    }
//                if(conn_bufspace(r->c) != 0){
                    rel_output(r);
                }else{
//                    TODO not sure if this implementation is correct or not, for now if the print buffer does not have enough space
//                    it will simply return (and wait for the sender side to resend)
//                    rel_output(r);
                    return;
                }

//                rel_output(r);


            }
        }else{
            fprintf(stderr, "\nHEREHEREHREHEHREHREHREHEHR55555555555555\n");
            //packet_seqno < r->RCV_NXT
            //make an ack packet with ackno = seqno + 1 and send it.
            if(packet_seqno != 0){
//                for debugging
                for(int i = 0; i < 1;i++){
                    struct ack_packet* ack_pac = xmalloc(sizeof(struct ack_packet));
//            ack_pac->ackno = htonl((uint32_t) (packet_seqno + 1));
                    ack_pac->ackno = htonl((uint32_t) (r->RCV_NXT));
                    ack_pac->len = htons ((uint16_t) 8);
                    ack_pac->cksum = (uint16_t) 0;
                    ack_pac->cksum = cksum(ack_pac, (int) 8);

                    conn_sendpkt(r->c, (packet_t *)ack_pac, (size_t) 8);
                    free(ack_pac);
                }

                return;
            }

        }
    }
}




void
rel_output (rel_t *r)
{

//  let's flush all in order packets in the receiving buffer into output
//  until we reached an insuccesive one.
    buffer_node_t* first_node = buffer_get_first(r->rec_buffer);

    if(first_node == NULL){
        return;
    }

    packet_t* packet = &(first_node->packet);
    uint16_t packet_length = ntohs(packet->len);
//  uint16_t packet_cksum = ntohs(packet->cksum);
    uint16_t packet_seqno = ntohl(packet->seqno);
    fprintf(stderr, "\nCALLED REL_OUTPUT??????????\n");
    if(first_node!=NULL){
        fprintf(stderr, "\nNULLLLLLLLNULLLLLLLNULLLL??????????\n");
    }else if (ntohl(packet->seqno) == (uint32_t) r->RCV_NXT){
        fprintf(stderr, "\nEQUAL  EQUAL  EUQAL ??????????\n");
    }
    while((first_node != NULL) &&
          (ntohl(packet->seqno) == (uint32_t) r->RCV_NXT) &&
          (conn_bufspace(r->c) >= (packet_length - 12))){
        fprintf(stderr, "\nENTER LOOP REL_OUTPUT!!!!!!!!!!!\n");
        packet_length = ntohs(packet->len);
        packet_seqno = ntohl(packet->seqno);

        if(is_EOF(packet)){
            //If we reached the EOF, we tell the conn_output and destroy the connection
//            fprintf(stderr, "\nRECEIVED   EOFEOFOEFOEFOEFOEFOEFOEFOEOFEOFEOFOEFEOFEOFEOFEOF\n");

            conn_output(r->c, packet->data, htons(0)); //send a signal to output by calling conn_output with len 0
            //send an ackno to the sender side

            buffer_remove_first(r->rec_buffer); //remove either EOF or Data packet whatever
            r->RCV_NXT ++;
            r->EOF_RECV_FLAG = 1;

            struct ack_packet* ack_pac = xmalloc(sizeof(struct ack_packet));
//            ack_pac->ackno = htonl((uint32_t) (packet_seqno + 1));
            ack_pac->ackno = htonl((uint32_t) (r->RCV_NXT));
            ack_pac->len = htons ((uint16_t) 8);
            ack_pac->cksum = (uint16_t) 0;
            ack_pac->cksum = cksum(ack_pac, (int) 8);
            conn_sendpkt(r->c, (packet_t *)ack_pac, (size_t) 8);
//            fprintf(r->fptr, "@send     ack =        %x\n"
//                    , ntohl(ack_pac->ackno));

            free(ack_pac);

            //destroy the connection
//            if(r->EOF_SENDER_FLAG == 1 && buffer_size(r->send_buffer) == 0 && buffer_size(r->rec_buffer) == 0){
//////                fprintf(r->fptr, "\nDESTROY DESTROY DESTROY DESTROY DESTROY DESTROY DESTROY DESTROY\n");
//
//                rel_destroy(r);
////TODO  does this break make a big difference?
//
//                break;
//            }
//            rel_destroy(r);

            if(r->EOF_ACK_RECV_FLAG && r->EOF_SENT_FLAG &&r->EOF_RECV_FLAG && !r->flush_busy && buffer_size(r->send_buffer) == 0){
//                fprintf(stderr, "@@@@@@@@@  DESTROYING!!!!!!!!!!!\n\n\n");
//                fsync(2);fsync(1);

                rel_destroy(r);
                return;
            }


        }else{ //is not EOF!!!!!
            //flush the normal data to the output
//            fprintf(r->fptr, "~~~~~~~~~packet_length: %x\n", packet_length);
            int bytes_flushed;
            if(conn_bufspace(r->c) >= (packet_length - 12)){
                r->flush_busy = 1;
                bytes_flushed = conn_output(r->c, packet->data, (size_t) (packet_length - 12));

//                fprintf(stderr, "~~~~~~~~~BYTES_FLUSHED: %x\n", bytes_flushed);
//                fprintf(stderr, "@flushed  ack =        %x, seq =       %x, len = %x\n"
//                        , ntohl(packet->ackno), ntohl(packet->seqno), packet_length );
//                fsync(2);fsync(1);

                buffer_remove_first(r->rec_buffer); //remove either EOF or Data packet whatever
                r->RCV_NXT ++;

                r->flush_busy = 0;

                struct ack_packet* ack_pac = xmalloc(sizeof(struct ack_packet));
//            ack_pac->ackno = htonl((uint32_t) (packet_seqno + 1));
                ack_pac->ackno = htonl((uint32_t) (r->RCV_NXT));
                ack_pac->len = htons ((uint16_t) 8);
                ack_pac->cksum = (uint16_t) 0;
                ack_pac->cksum = cksum(ack_pac, (int) 8);

                conn_sendpkt(r->c, (packet_t *)ack_pac, (size_t) 8);


                free(ack_pac);

            }else{
//                buffer_remove_first(r->rec_buffer); //remove either EOF or Data packet whatever
                bytes_flushed = -1;
//                fprintf(r->fptr, "~~~~~~~~~BYTES_FLUSHED: %x\n", bytes_flushed);
//                fprintf(r->fptr, "@flushed  ack =        %x, seq =       %x, len = %x\n"
//                        , ntohl(packet->ackno), ntohl(packet->seqno), packet_length );
            }
//

//TODO *****************************SPINING BUFSPACE******************************8
//            int bytes_flushed;
//            if(conn_bufspace(r->c) >= (packet_length - 12)){
////            while(conn_bufspace(r->c) < (packet_length - 12)){
//////                wait spin
////            }
//                r->flush_busy = 1;
//                bytes_flushed = conn_output(r->c, packet->data, (size_t) (packet_length - 12));
//
////                fprintf(stderr, "~~~~~~~~~BYTES_FLUSHED: %x\n", bytes_flushed);
////                fprintf(stderr, "@flushed  ack =        %x, seq =       %x, len = %x\n"
////                        , ntohl(packet->ackno), ntohl(packet->seqno), packet_length );
////                fsync(2);fsync(1);
//
//                buffer_remove_first(r->rec_buffer); //remove either EOF or Data packet whatever
//                r->RCV_NXT ++;
//
//                r->flush_busy = 0;
////            }else{
////                bytes_flushed = -1;
//////                fprintf(r->fptr, "~~~~~~~~~BYTES_FLUSHED: %x\n", bytes_flushed);
//////                fprintf(r->fptr, "@flushed  ack =        %x, seq =       %x, len = %x\n"
//////                        , ntohl(packet->ackno), ntohl(packet->seqno), packet_length );
////            }
//TODO *****************************SPINING BUFSPACE******************************8

    //            fprintf(r->fptr, "\nbytes_flushed : %d\n", bytes_flushed);
    //            fprintf(r->fptr, "sender buffer size : %d ,  receiver buffer size : %d\n",
    //                    buffer_size(r->send_buffer),  buffer_size(r->rec_buffer));

//                struct ack_packet* ack_pac = xmalloc(sizeof(struct ack_packet));
////            ack_pac->ackno = htonl((uint32_t) (packet_seqno + 1));
//                ack_pac->ackno = htonl((uint32_t) (r->RCV_NXT));
//                ack_pac->len = htons ((uint16_t) 8);
//                ack_pac->cksum = (uint16_t) 0;
//                ack_pac->cksum = cksum(ack_pac, (int) 8);
////                fprintf(r->fptr, "@@@@@send     ack =        %x\n"
////                        , ntohl(ack_pac->ackno));
////                for(int i = 10; i >0; i--){
//                     conn_sendpkt(r->c, (packet_t *)ack_pac, (size_t) 8);
////                }
//
//                free(ack_pac);
//woeif
//            buffer_remove_first(r->rec_buffer); //remove either EOF or Data packet whatever
//            r->RCV_NXT ++;

        }

//        buffer_remove_first(r->rec_buffer); //remove either EOF or Data packet whatever
//        r->RCV_NXT ++;
        first_node = buffer_get_first(r->rec_buffer);
        if(first_node != NULL){
            packet = &(first_node->packet);
        }

        packet_length = ntohs(packet->len);
        packet_seqno = ntohl(packet->seqno);
    }

}


//void
//rel_read (rel_t *s)
//{
//    /*First we need to check if there is still space in sender sliding window buffer*/
//    int SND_UNA = s->SND_UNA;
//    int SND_NXT = s->SND_NXT;
//    int MAXWND = s->MAXWND;
//    if((SND_NXT - SND_UNA < MAXWND)&& !(s->EOF_ERR_FLAG)) {
//        //there is still space in the sliding window
//        //allocate space for a packet
//        packet_t *packet = (packet_t *) xmalloc(512);
//        //read from conn_input, it returns the number of bytes
//        // 0 if there is no data currently available, and -1 on EOF or error.
//        int read_byte = conn_input(s->c, packet->data, 500);
//        if (read_byte == -1) {
//            //we have received an EOF signal. Create an EOF packet and Mark it with the Flag
//            s->EOF_ERR_FLAG = 1;
//            //which has "zero length payload", and we should also push this packet in the buffer
//            //        packet->data = ()0;
//            packet->len = htons((uint16_t) 12);
//            packet->ackno = htonl((uint32_t) 0); //EOF packet, ackno doesn't matter
//            packet->seqno = htonl((uint32_t) SND_NXT);
//            //moving the upper bound index
//            s->SND_NXT = s->SND_NXT + 1;
//
//            packet->cksum = (uint16_t) 0;
//            packet->cksum = cksum(packet, 12);
//
//            //finished packing the EOF packek, push it into the send buffer
//            buffer_insert(s->send_buffer, packet, get_current_system_time());
//            conn_sendpkt(s->c, packet, (size_t) 12);
//            free(packet);
//            rel_read(s);
//            return;
//        } else if (read_byte == 0) {
//            free(packet);
//            return; // the lib will call rel_read again on its own, do not loop calling!
//        } else {
//            packet->len = htons((uint16_t)(12 + read_byte));
//            packet->ackno = htonl((uint32_t) 10); //data packet, ackno doesn't matter
//            packet->cksum = htons((uint16_t) 0);
//            packet->seqno = htonl((uint32_t) SND_NXT);
////            fprintf(r->fptr, "packing data into pac_seq: %d\n", SND_NXT);
//
//            //moving the sliding window
//            s->SND_NXT = s->SND_NXT + 1;
//
//            packet->cksum = (uint16_t) 0;
//            packet->cksum = cksum(packet, 12 + read_byte);
//
//            //finished packing the data packet, push it into the send buffer
//            buffer_insert(s->send_buffer, packet, get_current_system_time());
////            fprintf(r->fptr, "sender buffer size : %d ,  receiver buffer size : %d\n",
////                    buffer_size(s->send_buffer),  buffer_size(s->rec_buffer));
//            conn_sendpkt(s->c, packet, (size_t) 12 + read_byte);
//            free(packet);
//            rel_read(s);
//        }
//
//    }
//    return NULL;
//}




////// ****************** The while implementation of rel_read *****************
void
rel_read (rel_t *s)
{
    /*First we need to check if there is still space in sender sliding window buffer*/
    int SND_UNA;
    int SND_NXT;
    int MAXWND;
    int read_byte;
    SND_UNA = s->SND_UNA;
    SND_NXT = s->SND_NXT;
    MAXWND = s->MAXWND;

    if((s->EOF_SENT_FLAG)){

       return;
    }

    while((SND_NXT - SND_UNA < MAXWND)&& (!(s->EOF_SENT_FLAG))) {
        packet_t *packet = (packet_t *) xmalloc(512);
        memset(packet, 0 , sizeof(packet_t));
//    while((buffer_size(s->send_buffer) < MAXWND)&& (!(s->EOF_SENDER_FLAG))) {
        read_byte = conn_input(s->c, packet->data, 500);
//        fprintf(r->fptr, "LOOOPING!!!!! \n");
        //there is still space in the sliding window
        //allocate space for a packet
        if (read_byte == -1) {
            //we have received an EOF signal. Create an EOF packet and Mark it with the Flag
            s->EOF_SENT_FLAG = 1;
            s->EOF_seqno = s->SND_NXT;

            //which has "zero length payload", and we should also push this packet in the buffer
            //        packet->data = ()0;
            packet->len = htons((uint16_t) 12);
            packet->ackno = htonl((uint32_t) 0); //EOF packet, ackno doesn't matter
            packet->seqno = htonl((uint32_t) SND_NXT);
            //moving the upper bound index
            s->SND_NXT = s->SND_NXT + 1;

            packet->cksum = (uint16_t) 0;
            packet->cksum = cksum(packet, 12);

            //finished packing the EOF packek, push it into the send buffer
            buffer_insert(s->send_buffer, packet, get_current_system_time());
            conn_sendpkt(s->c, packet, (size_t) 12);
//            free(packet);


        } else if (read_byte == 0) {
            free(packet);
            break;
// the lib will call rel_read again on its own, do not loop calling!
        } else {
            packet->len = htons((uint16_t)(12 + read_byte));
            packet->ackno = htonl((uint32_t) 0); //data packet, ackno doesn't matter
            packet->cksum = htons((uint16_t) 0);
            packet->seqno = htonl((uint32_t) SND_NXT);
//            fprintf(stderr, "packing data into pac_seq: %d\n", SND_NXT);

            //moving the sliding window
            s->SND_NXT = s->SND_NXT + 1;

            packet->cksum = (uint16_t) 0;
            packet->cksum = cksum(packet, 12 + read_byte);

            //finished packing the data packet, push it into the send buffer
            buffer_insert(s->send_buffer, packet, get_current_system_time());
//            fprintf(r->fptr, "sender buffer size : %d ,  receiver buffer size : %d\n",
//                    buffer_size(s->send_buffer),  buffer_size(s->rec_buffer));
            conn_sendpkt(s->c, packet, (size_t) (12 + read_byte));
//            free(packet);
        }
        free(packet);
//        packet = (packet_t *) xmalloc(512);
        SND_UNA = s->SND_UNA;
        SND_NXT = s->SND_NXT;
        MAXWND = s->MAXWND;

    }
//    return NULL;
}

void
rel_timer ()
{
    // Go over all reliable senders, and have them send out
    // all packets whose timer has expired
    rel_t *current = rel_list;
    while (current != NULL) {
        // go over the sender buffer and resend expired un-acked packets
        buffer_node_t* node = buffer_get_first(current->send_buffer);
        packet_t* packet;
//        currently only checking the first 3 un-acked pac
        int i = 1;
//        fprintf(r->fptr, "\ntimer!  SND_UNA: %d  ,  SND_NXT: %d  , RCV_NXT:　%d\n",
//                current->SND_UNA, current->SND_NXT, current->RCV_NXT );
//        fprintf(r->fptr, "sender buffer size : %d ,  receiver buffer size : %d\n",
//                buffer_size(current->send_buffer),  buffer_size(current->rec_buffer));
//        fprintf(r->fptr, "current node packet seqno: %d", ntohl((&node->packet)->seqno));
        while(i > 0 && node != NULL){
          if(node != NULL) {
//            fprintf(r->fptr, "\nhere\n");
              packet = &node->packet;
              long cur_time = get_current_system_time();
              long last_time = node->last_retransmit;
              long timeout = current->timeout;

              if ((cur_time - last_time) >= timeout) {
//                fprintf(r->fptr, "retransmitting packet with seqno : %d", ntohs(packet->seqno) );
                  //timeout, resend packets
//                fprintf(r->fptr, "RETRASNMITTING!  pac_seqno : %x \n", packet->seqno);
                  conn_sendpkt(current->c, packet, (size_t)(ntohs(packet->len)));
                  //also update the retransmittion time of this node
                  node->last_retransmit = cur_time;
              }

          }
            i--;
            node = node->next;
        }
//        current = rel_list->next;
        current = current->next;
//        free(packet);
//        free(node);
    }
}
////// ****************** The recursive implementation of rel_read *****************
//void
//rel_read (rel_t *s) {
//    /*First we need to check if there is still space in sender sliding window buffer*/
//    int SND_UNA = s->SND_UNA;
//    int SND_NXT = s->SND_NXT;
//    int MAXWND = s->MAXWND;
//    if ((SND_NXT - SND_UNA < MAXWND) && !(s->EOF_ERR_FLAG)) {
//        //there is still space in the sliding window
//        //allocate space for a packet
//        packet_t *packet = (packet_t *) xmalloc(512);
//        //read from conn_input, it returns the number of bytes
//        // 0 if there is no data currently available, and -1 on EOF or error.
//        int read_byte = conn_input(s->c, packet->data, 500);
//        if (read_byte == -1) {
//            //we have received an EOF signal. Create an EOF packet and Mark it with the Flag
//            s->EOF_ERR_FLAG = 1;
//            //which has "zero length payload", and we should also push this packet in the buffer
//            //        packet->data = ()0;
//            packet->len = htons((uint16_t) 12);
//            packet->ackno = htonl((uint32_t) 0); //EOF packet, ackno doesn't matter
//            packet->seqno = htonl((uint32_t) SND_NXT);
//            //moving the upper bound index
//            s->SND_NXT = s->SND_NXT + 1;
//
//            packet->cksum = (uint16_t) 0;
//            packet->cksum = cksum(packet, 12);
//
//            //finished packing the EOF packek, push it into the send buffer
//            buffer_insert(s->send_buffer, packet, get_current_system_time());
//            conn_sendpkt(s->c, packet, (size_t) 12);
//            free(packet);
//            rel_read(s);
//            return;
//        } else if (read_byte == 0) {
//            free(packet);
//            return; // the lib will call rel_read again on its own, do not loop calling!
//        } else {
//            packet->len = htons((uint16_t)(12 + read_byte));
//            packet->ackno = htonl((uint32_t) 0); //data packet, ackno doesn't matter
//            packet->cksum = htons((uint16_t) 0);
//            packet->seqno = htonl((uint32_t) SND_NXT);
////            fprintf(r->fptr, "packing data into pac_seq: %d\n", SND_NXT);
//
//            //moving the sliding window
//            s->SND_NXT = s->SND_NXT + 1;
//
//            packet->cksum = (uint16_t) 0;
//            packet->cksum = cksum(packet, 12 + read_byte);
//
//            //finished packing the data packet, push it into the send buffer
//            buffer_insert(s->send_buffer, packet, get_current_system_time());
////            fprintf(r->fptr, "sender buffer size : %d ,  receiver buffer size : %d\n",
////                    buffer_size(s->send_buffer),  buffer_size(s->rec_buffer));
//            conn_sendpkt(s->c, packet, (size_t) 12 + read_byte);
//            free(packet);
//            rel_read(s);
//            return;
//        }
//
//    }
//}
////// *******The recursive implementation of rel_read *****not in use****

long get_current_system_time()
{ // now in milliseconds
    struct timeval now;
    gettimeofday(&now, NULL);
    long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
    return now_ms;
}

int is_EOF(packet_t* packet){
    if(ntohs(packet->len) == (uint16_t) 12){
        return 1;
    }else{
        return 0;
    }
}

int is_ACK(packet_t* packet){
    if(ntohs(packet->len) == (uint16_t) 8){
        return 1;
    }else{
        return 0;
    }
}

int MAX(int a, int b){
    if(a > b){
        return a;
    }else{
        return b;
    }
}
