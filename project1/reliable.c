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
#include <inttypes.h>

#include "rlib.h"
#include "buffer.h"


#define DATA_MAX_LENGTH 500
#define PACKET_MAX_SIZE 512
#define PAK_HEADER_SIZE 12
#define ACK_SIZE 8

//done at 17:16
packet_t * makePacFromInput(rel_t *r);
int isPacAck(packet_t *packet);
int savePacketToSendBuffer(packet_t *packet, rel_t *s);
int packetCorrupted(packet_t *packet, size_t received_length);
int passDataToConnOutput(rel_t *r);
int isEOF(packet_t *packet);
void makeANDsendAck(rel_t *relState, uint32_t ackno);
void packetToHostOrder(packet_t *pak);
void sender_window_sliding_send(rel_t *s);
void sender_window_sliding_ack(rel_t *s, packet_t *ackPak);
void rec_window_sliding_data(rel_t *r, packet_t *Pak);
void packetToNetworkOrder(packet_t *packet);
void packetToHostOrder(packet_t *pak);
uint16_t computeChecksum(packet_t *pac, int pacLen);
void pacPreprocess(packet_t *packet);


struct reliable_state {
    rel_t *next;            /* Linked list for traversing all connections */
    rel_t **prev;

    conn_t *c;            /* This is the connection object */

    /* Add your own data fields below this */
    // ...
    buffer_t *send_buffer;
    // ...
    buffer_t *rec_buffer;
    // ...

    uint32_t current_seqno;
    //the base of the sliding window
    uint32_t base_seqno;
    //the packet which should be acked next
    uint32_t next_seqno;
    //send/receive window
    uint32_t window;
    //rcv_nxt in the slides
    uint32_t rcv_nex;
    //time out
    long timout;
    //EOF flag, true if EOF has been reached
    int EOFflag;

    int MaxWindow;
};
rel_t *rel_list;//a list of reliable_state

/* Creates a new reliable protocol session, returns NULL on failure.
* ss is always NULL */
rel_t *
rel_create(conn_t *c, const struct sockaddr_storage *ss,
           const struct config_common *cc) {
    rel_t *r;

    r = xmalloc(sizeof(*r));
    memset(r, 0, sizeof(*r));

    if (!c) {
        c = conn_create(r, ss);
        if (!c) {
            free(r);
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
    //pass window size in
    r->MaxWindow = cc->window;

    //maintain an overall seq number, will be incremented each time
    // a new packet is created
    r->current_seqno = 0;

    r->base_seqno = 0;
    r->next_seqno = 0;
    r->window = r->next_seqno - r->base_seqno;

    // sender side
    r->send_buffer = xmalloc(sizeof(buffer_t));
    r->send_buffer->head = NULL;



    // receiver side
    r->rec_buffer = xmalloc(sizeof(buffer_t));
    r->rec_buffer->head = NULL;
    r->rcv_nex = 1;

    // timeout
    r->timout = cc->timeout;
    //EOF flag
    r->EOFflag = 0;

    return r;
}

void
rel_destroy(rel_t *r) {
    if (r->next) {
        r->next->prev = r->prev;
    }
    *r->prev = r->next;
    conn_destroy(r->c);

    /* Free any other allocated memory here */
    buffer_clear(r->send_buffer);
    free(r->send_buffer);
    buffer_clear(r->rec_buffer);
    free(r->rec_buffer);
    // ...

}

// n is the expected length of pkt
void
rel_recvpkt(rel_t *r, packet_t *pkt, size_t n) {


    if (n < ntohs(pkt->len) || packetCorrupted(pkt, n)) {
        //received packet is corrupted, waiting for resend(wait until timeout)
        //TODO NOTHING
    } else {
        packetToHostOrder(pkt);
        if (isPacAck(pkt)) {
            //TODO if it is a Ack Packet
            //move the packet out of the buffer, and
            //and call real_read, which will fill the new slots in the send window
            sender_window_sliding_ack(r, pkt);

//            fprintf(stderr, "received ack, check if correct packet is removed in send buffer\n");
//            buffer_print(r->send_buffer);
        } else {
            if (isEOF(pkt)) {//the packet is EOF packet, this side should stop receiving
//                fprintf(stderr,"dealing with EOF");
//                fprintf(stderr,"packetSEQNO %d \n", pkt->seqno);
//                fprintf(stderr,"packetLEN %d \n", pkt->len);

                rec_window_sliding_data(r, pkt);
            } else {//normal data packet

                //TODO 这里应该被重写，用rec sliding window (done)
//                makeANDsendAck (r, pkt->seqno + 1);
//                savePacketToRecvBuffer(pkt, r);
//                rel_output(r);
                //fprintf(stderr, "rec sliding gets called");
                rec_window_sliding_data(r, pkt);
            }
        }
    }
}


void
rel_read(rel_t *s) {
    //   fprintf(stderr,"CALLED******CALLED*****CALLED ");
    /*create space for packet*/
//    //packet_t *packet = makePacFromInput (s);
//    if(packet == NULL){
// //       fprintf(stderr,"empty");
//    }
//    /*fit the data into the packet by calling conn_input*/
// //   fprintf(stderr,"anything");
//
//    pacPreprocess (packet);
//
////FOR TEST PACKET WELL WRITTEN
////        fprintf(stderr, "packet content");
////        fprintf(stderr, "%d",packet->data[0]);
//    savePacketToSendBuffer(packet,s);


    //这里应该用sliding window protocol 重写,（已经重写了）
    if (s->EOFflag == 0) {
        sender_window_sliding_send(s);
    }


    //conn_sendpkt (s->c, packet, (size_t) packetLength);

}


void
rel_output(rel_t *r) {
    //   fprintf(stderr,"receive buffer");
    // buffer_print(r->rec_buffer);
    int printedBytes = passDataToConnOutput(r);
//    if (flushedBytes != 0) {
//        /* send ack back only after flushing ALL the packet */
//        // makeANDsendAck (r, r->current_seqno + 1);
//        //relState->nextInOrderSeqNo = r->lastReceivedPacketSeqno + 1;
//        //relState->serverState = WAITING_DATA_PACKET;
//    }

    //   fprintf(stderr,"output side");

}


void
rel_timer() {
    // Go over all reliable senders, and have them send out
    // all packets whose timer has expired
    rel_t *current = rel_list;
    while (current != NULL) {
        // .....................
        struct timeval now;
        gettimeofday(&now, NULL);
        long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;

        buffer_node_t *bf = buffer_get_first(current->send_buffer);
        if (bf != NULL) {
            long lastTime = bf->last_retransmit;
            if ((now_ms - lastTime) >= current->timout) { //timeout, resend the first packet
                //update the retransmission time
                bf->last_retransmit = now_ms;
                packet_t pkt = bf->packet;
                conn_sendpkt(current->c, &pkt, (size_t) (ntohs(pkt.len)));
            }
        }
        //......................
        current = rel_list->next;
    }
}


/******************************HELPER FUNCTIONS*******************************/

// check checksum and length, if doesn't match, the packet is corrupted
int packetCorrupted(packet_t *pac, size_t recLen) {
    int pacLen = (int) ntohs(pac->len);

    /* If we received fewer bytes than the packet's size declare corruption. */
    if (recLen < (size_t) pacLen){
        return 1;
    }

    uint16_t pakChecksum = pac->cksum;
    uint16_t computeChecksumNo = computeChecksum(pac, pacLen);

    return pakChecksum != computeChecksumNo;
}

uint16_t computeChecksum(packet_t *pac, int pacLen) {
    pac->cksum = 0;

    uint16_t cksumNo = cksum((void *) pac, pacLen);
    return cksumNo;
}

int isPacAck(packet_t *packet) {
    /*the packet should be the one after receiving (by either sender or receiver)
     * check weather a packet is an ack packet or data packet
     * if it's ack packet return 0, else return 1*/
    if (packet->len == 8) {
        // an ack packet
        return 1;
    } else {
        return 0;
    }

}

int isEOF(packet_t *packet) {
    /*
     * return 1 if the packet is EOF packet, else return 0
     */
    if (packet->len == 12) {
        return 1;
    } else {
        return 0;
    }
}



void pacPreprocess(packet_t *pac) {
    int pacLen = (int) (pac->len);

    packetToNetworkOrder(pac);
    pac->cksum = computeChecksum(pac, pacLen);
}

packet_t * makePacFromInput(rel_t *r) {
    packet_t *pac;
    pac = xmalloc(sizeof(*pac));

    //try make a max length data packet
    int ReadLength = conn_input(r->c, pac->data, DATA_MAX_LENGTH);

    //no input
    if (ReadLength == 0)
    {
        free(pac);
        return NULL;
    }

    // if encountered an EOF then make a zero byte data, otherwise read normally
    if(ReadLength == -1){
        pac->len = (uint16_t) PAK_HEADER_SIZE;//created a EOF file, namely only header
    }else{
        pac->len = (uint16_t) (PAK_HEADER_SIZE + ReadLength);
    }


    pac->ackno = (uint32_t) 1; /* not piggybacking acks, don't ack any packets */
    int temp = r->current_seqno;
    pac->seqno = (uint32_t) (temp + 1);
    //update relState seqno number
    r->current_seqno = (r->current_seqno) + 1;

    return pac;
}

int savePacketToSendBuffer(packet_t *packet, rel_t *s) {

    //don't know what to pass to lastRetransmission time, temporarily the current system time.
    //even if the packet is sent for the first time
    struct timeval now;
    gettimeofday(&now, NULL);
    long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;

    buffer_insert(s->send_buffer, packet, now_ms);
    return 1;
}


int passDataToConnOutput(rel_t *r) {
    size_t bufferSpace = conn_bufspace(r->c);

    if (bufferSpace == 0) {
        return 0;
    }
//get the first packet in the receive buffer
    packet_t pkt = buffer_get_first(r->rec_buffer)->packet;
//output data in the terminal, meanwhile return how many bytes were output
    int bytesOutput = conn_output(r->c, pkt.data, (size_t) (pkt.len - (uint16_t) 12));
    return bytesOutput;
}

void makeANDsendAck(rel_t *r, uint32_t ackno) {
    struct ack_packet *ackPacket;
    ackPacket = xmalloc(sizeof(*ackPacket));

    ackPacket->len = (uint16_t) ACK_SIZE;
    ackPacket->ackno = ackno;


    int len = ackPacket->len;
    pacPreprocess((packet_t *) ackPacket);
    conn_sendpkt(r->c, (packet_t *) ackPacket, (size_t) len);

    free(ackPacket);
}


//convert packet to host order
void packetToHostOrder(packet_t *pak) {
    pak->len = ntohs(pak->len);
    pak->ackno = ntohl(pak->ackno);

    /* if the packet is a data packet it additionally has a seqno that has
       to be converted to host byte order */
    if (pak->len != ACK_SIZE)
        pak->seqno = ntohl(pak->seqno);
}

void packetToNetworkOrder(packet_t *packet) {
    /* if the packet is a data packet it also has a seqno that has to be converted to
       network byte order */
    if (packet->len != ACK_SIZE)
        packet->seqno = htonl(packet->seqno);

    packet->len = htons(packet->len);
    packet->ackno = htonl(packet->ackno);
}

void sender_window_sliding_send(rel_t *s) {
    uint32_t base = s->base_seqno;
    uint32_t nextSeq = s->next_seqno;
    uint32_t windowSize = s->MaxWindow;

    //TODO destroy hasn't been implemented

    if (buffer_size(s->send_buffer) < windowSize) {
        packet_t *packet = makePacFromInput(s);
        if (packet != NULL) {
            int packetLength = packet->len;

            if (isEOF(packet)) {
                s->EOFflag = 1; //set flag to true
                /*
                 * When you read an EOF, you should
                 * send a zero-length payload (12-byte packet) to the other side to indicate the end of file
                 * condition.
                 */
                pacPreprocess(packet);
                savePacketToSendBuffer(packet, s);
                conn_sendpkt(s->c, packet, (size_t) packetLength);

                free(packet);


            } else {
                pacPreprocess(packet);
                savePacketToSendBuffer(packet, s);
                conn_sendpkt(s->c, packet, (size_t) packetLength);

                free(packet);
            }
        }
    }
}

/*
 * this method is called when an ack packet is received by the sender's side
 * it removes the accordingly packet saved in the sender buffer
 * and increments the base seqno number towards bigger segno
 *
 */
void sender_window_sliding_ack(rel_t *s, packet_t *ackPak) {
    //Remove all buffer nodes until (lower-than exclusive <) a certain packet sequence number from the buffer.
    int numberOfRemovedSlots = buffer_remove(s->send_buffer, ackPak->ackno);


    rel_read(s);

///version 2  NOT WORKING
//    while(buffer_size(s->send_buffer)<s->MaxWindow) {
//        rel_read(s);
//    }
}


void rec_window_sliding_data(rel_t *r, packet_t *pak) {
//if receiving a pack with seqno < expected seqno, just send an ack and return
    if (pak->seqno < r->rcv_nex) {
        makeANDsendAck(r, pak->seqno + 1);
        return;
    }

    uint32_t windowSize = r->MaxWindow;

    //the received pack is a data pac
    if (buffer_size(r->rec_buffer) < windowSize) {//if the window still has some room

        struct timeval now;
        gettimeofday(&now, NULL);
        long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;


        packetToHostOrder(pak);

        buffer_insert(r->rec_buffer, pak, now_ms);
        //get the first buffer node in the receive buffer
        buffer_node_t *bnCurrent = buffer_get_first(r->rec_buffer);
        packet_t nodePac = bnCurrent->packet;

        //    packetToHostOrder(pak);
        if (bnCurrent != NULL && ntohl(nodePac.seqno) == r->rcv_nex) { // if the first pac in buffer is in order pac
            int index = r->rcv_nex;//be aware this is the first node, the loop start from the first node

            //if receiving a pack with seqno< expected seqno
//            fprintf(stderr,"##########");
//            fprintf(stderr,"INDEX: %d      ", index);
//            buffer_print(r->rec_buffer);
            while (buffer_contains(r->rec_buffer, index)) {//traverse the rec buffer as far as possible

                // if(conn_bufspace(r->c)<nodePac.len){return;}

                if (isEOF(&nodePac)) {//EOF EOF EOF EOF
//                        fprintf(stderr,"ENTER EOF HANDLER");
                    conn_output(r->c, nodePac.data, htons(0));

                    makeANDsendAck(r, nodePac.seqno + 1);

                    /* destroy the connection only if our client has finished transmitting */
                    rel_destroy(r);
                } else {
                    conn_output(r->c, nodePac.data, htons(nodePac.len) - (uint16_t) 12);
                    //   fprintf(stderr,"WHATWHATWHAT");
                    makeANDsendAck(r, index + 1);  //send ack with ackno = currentPacSeqno +1
                    //    fprintf(stderr,"whywhywhy");
                    buffer_remove(r->rec_buffer, index + 1);
                }
                index = index + 1;
                r->rcv_nex = index;
                if (bnCurrent->next != NULL) {
                    bnCurrent = bnCurrent->next;
                    nodePac = bnCurrent->packet;
                }
            }

        } else {// is the coming pac is out of oder pac
            //simply saved it in the buffer and do nothing
        }
    }
}
