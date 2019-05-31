/* Filename: dr_api.c */

/* include files */
#include <arpa/inet.h>  /* htons, ... */
#include <sys/socket.h> /* AF_INET */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include "dr_api.h"
#include "rmutex.h"
#include <inttypes.h>


// debugging tools
#define DEBUG 1
#define LOOPDEBUG 0

/* internal data structures */
#define INFINITY 16

#define RIP_IP htonl(0xE0000009)

#define RIP_COMMAND_REQUEST  1
#define RIP_COMMAND_RESPONSE 2
#define RIP_VERSION          2

#define RIP_ADVERT_INTERVAL_SEC 10
#define RIP_TIMEOUT_SEC 20
#define RIP_GARBAGE_SEC 20

/** information about a route which is sent with a RIP packet */
typedef struct rip_entry_t {
    uint16_t addr_family;
    uint16_t pad;           /* just put zero in this field */
    uint32_t ip;
    uint32_t subnet_mask;
    uint32_t next_hop;
    uint32_t metric;
} __attribute__ ((packed)) rip_entry_t;

/** the RIP payload header */
typedef struct rip_header_t {
    char        command;
    char        version;
    uint16_t    pad;        /* just put zero in this field */
    rip_entry_t entries[0];
} __attribute__ ((packed)) rip_header_t;

/** a single entry in the routing table */
typedef struct route_t {
    uint32_t subnet;        /* destination subnet which this route is for */
    uint32_t mask;          /* mask associated with this route */
    uint32_t next_hop_ip;   /* next hop on on this route */
    uint32_t outgoing_intf; /* interface to use to send packets on this route */
    uint32_t cost;
    struct timeval last_updated;

    int is_garbage; /* boolean which notes whether this entry is garbage */

    route_t* next;  /* pointer to the next route in a linked-list */
} route_t;


/* internal variables */

/* a very coarse recursive mutex to synchronize access to methods */
static rmutex_t coarse_lock;

/** how mlong to sleep between periodic callbacks */
static unsigned secs_to_sleep_between_callbacks;
static unsigned nanosecs_to_sleep_between_callbacks;


/* these static functions are defined by the dr */

/*** Returns the number of interfaces on the host we're currently connected to.*/
static unsigned (*dr_interface_count)();

/*** Returns a copy of the requested interface.  All fields will be 0 if the an* invalid interface index is requested.*/
static lvns_interface_t (*dr_get_interface)(unsigned index);

/*** Sends specified dynamic routing payload.** @param dst_ip   The ultimate destination of the packet.
 ** @param next_hop_ip  The IP of the next hop (either a router or the final dst).** @param outgoing_intf  Index of the interface to send the packet from.
 ** @param payload  This will be sent as the payload of the DR packet.  The caller*                 is reponsible for managing the memory associated with buf*                 (e.g. this function will NOT free buf).
 ** @param len      The number of bytes in the DR payload.*/
static void (*dr_send_payload)(uint32_t dst_ip,
                               uint32_t next_hop_ip,
                               uint32_t outgoing_intf,
                               char* /* borrowed */,
                               unsigned);


/* internal functions */
long get_time();
void print_ip(int ip);
void print_routing_table(route_t *head);
/* internal lock-safe methods for the students to implement */
static next_hop_t safe_dr_get_next_hop(uint32_t ip);
static void safe_dr_handle_packet(uint32_t ip, unsigned intf,
                                  char* buf /* borrowed */, unsigned len);
static void safe_dr_handle_periodic();
static void safe_dr_interface_changed(unsigned intf,
                                      int state_changed,
                                      int cost_changed);

/*** This simple method is the entry point to a thread which will periodically* make a callback to your dr_handle_periodic method.*/
static void* periodic_callback_manager_main(void* nil) {
    struct timespec timeout;

    timeout.tv_sec = secs_to_sleep_between_callbacks;
    timeout.tv_nsec = nanosecs_to_sleep_between_callbacks;
    while(1) {
        nanosleep(&timeout, NULL);
        dr_handle_periodic();
    }

    return NULL;
}

next_hop_t dr_get_next_hop(uint32_t ip) {
    next_hop_t hop;
    rmutex_lock(&coarse_lock);
    hop = safe_dr_get_next_hop(ip);
    rmutex_unlock(&coarse_lock);
    return hop;
}

void dr_handle_packet(uint32_t ip, unsigned intf, char* buf /* borrowed */, unsigned len) {
    rmutex_lock(&coarse_lock);
    safe_dr_handle_packet(ip, intf, buf, len);
    rmutex_unlock(&coarse_lock);
}

void dr_handle_periodic() {
    rmutex_lock(&coarse_lock);
    safe_dr_handle_periodic();
    rmutex_unlock(&coarse_lock);
}

void dr_interface_changed(unsigned intf, int state_changed, int cost_changed) {
    rmutex_lock(&coarse_lock);
    safe_dr_interface_changed(intf, state_changed, cost_changed);
    rmutex_unlock(&coarse_lock);
}


/* ****** It is recommended that you only modify code below this line! ****** */
//TODO TODO TODO TODO TODO TODO
//
long last_updated_time;
static route_t* forward_table_first;
static route_t* neighbors_first;

/*************************DEFINE NEW HELPING FUNCTIONS******************************/


void advertise_to_neighbors(int num_interfaces);
route_t* longest_match_prefix_route(route_t* forward_table_starting, uint32_t targetIP, route_t* targetRoute);
int check_ip_in_list(route_t* list, uint32_t targetIP);
int validate_packet(rip_header_t* rip_header, uint32_t ip_host, unsigned interface);
void clean_forward_list(route_t* route_list);
int check_ip_in_list_return_route(route_t* list, uint32_t targetIP, route_t* targetRoute);
void restore_route_from_neighbor_list(route_t* neighbor_list_route, route_t* forward_list_route);
void clean_neighbor_list(route_t* neighbors_first);


/************************DEFINE NEW HELPING FUNCTIONS*********************************/





/**
 * This function will be called before any other method here.  It may only be
 * called ONCE.  The function pointer passed as an argument tells the DR API how
 * it can send packets.
 *     dst_ip         The ultimate desination of the packet.
 *     next_hop_ip    Next hop IP address (either a router or the ultimate dest)
 *     outgoing_intf  Index of the interface to send this packet out of
 *
 * This method initializes any data structures used internally by this library.
 * It may also start a thread to take care of periodic tasks.
 */

void dr_init(unsigned (*func_dr_interface_count)(),
             lvns_interface_t (*func_dr_get_interface)(unsigned index),
             void (*func_dr_send_payload)(uint32_t dst_ip,
                                          uint32_t next_hop_ip,
                                          uint32_t outgoing_intf,
                                          char* /* borrowed */,
                                          unsigned)) {
    pthread_t tid;

    /* save the functions the DR is providing for us */
    dr_interface_count = func_dr_interface_count;
    dr_get_interface = func_dr_get_interface;
    dr_send_payload = func_dr_send_payload;

    /* initialize the recursive mutex */
    rmutex_init(&coarse_lock);

    /* initialize the amount of time we want between callbacks */
    secs_to_sleep_between_callbacks = 1;
    nanosecs_to_sleep_between_callbacks = 0;

    /* start a new thread to provide the periodic callbacks */
    if(pthread_create(&tid, NULL, periodic_callback_manager_main, NULL) != 0) {
        fprintf(stderr, "pthread_create failed in dr_initn");
        exit(1);
    }

    /* do initialization of your own data structures here */
    //TODO for all interfaces
    //For all interfaces, we maintain an entry for it in the forward table
    //forward table contains all routes including direct and indirect

    // and for all direct neighbors, we also maintain a separate list,
    // this saves a lot of time to handle corner cases involving direct link
    // especially scenarios like indirect route is shorter than a direct link


    for (int i = 0; i < (int)dr_interface_count(); i++){
        lvns_interface_t curr_if = dr_get_interface(i);
        int valid_interface = (curr_if.cost < 16) && (curr_if.enabled);
        if(valid_interface){
            //The interface is valid, we first malloc a route
            route_t* route_temp = (route_t*)malloc(sizeof(route_t));
            //and initialize it

            //WARNING for one hop routes, the destination is the neighbor itself,
            // I use a 0 to mark the single hop route
            // this information is important for advertisement
            // TODO check if we should initialize the ip with the router's own IP
            route_temp->next_hop_ip = 0;   //this should by default be 0, for self destined route
            route_temp->outgoing_intf = i;  //this route is about the i-th interface

            route_temp->is_garbage = 0;
            route_temp->cost = curr_if.cost;
            route_temp->subnet = ntohl(curr_if.ip);
            route_temp->mask = ntohl(curr_if.subnet_mask);
            
            struct timeval t;
            t.tv_sec = -1; //neighboring link has TTL = -1
            t.tv_usec = 0; //dummy initialization, will be filled by gettimeofday
            route_temp->last_updated = t;

            //push it to the direct route linked list's FIRST place
            // this can avoid traverse of the entire list
            route_t* forward_first_old = forward_table_first;
            route_temp->next = forward_first_old;
            forward_table_first = route_temp;

            // since it's neighbors, we keep a copy for neighbor list as well
            route_t* copy_route = (route_t*) malloc(sizeof(route_t));
            memcpy(copy_route, route_temp, sizeof(*route_temp));
            route_t* neighbors_first_old = neighbors_first;
            copy_route->next = neighbors_first_old;
            neighbors_first = route_temp;

        }
    }
    last_updated_time = get_time();
    // finished initializing all interfaces corresponding entries
    // now advertise the update to neighbors.
    advertise_to_neighbors((int)dr_interface_count());

    printf("*********printing full forward table*********\n");
    print_routing_table(forward_table_first);
    printf("*********printing neighbor table*********\n");
    print_routing_table(neighbors_first);
}

next_hop_t safe_dr_get_next_hop(uint32_t ip) {
    clean_forward_list(forward_table_first);
    next_hop_t hop;
    hop.interface = 0;
    hop.dst_ip = 0;
    /* determine the next hop in order to get to ip */
    uint32_t ip_host = ntohl(ip);
    if(DEBUG)  printf("in safe_dr_get_next_hop: \n");
    if(DEBUG)  print_ip(ip_host);
    // we find the most specific matching route using ip.
    route_t* best_matching_route;
    best_matching_route = NULL;
    best_matching_route = longest_match_prefix_route(forward_table_first, ip_host, best_matching_route);

    if(best_matching_route==NULL){
        printf("best matching == NULL\n");
        hop.dst_ip = htonl((u_int32_t)-1); //return 0xFFFFFFFF if this route does not exist
        hop.interface = 0; //idk.. doesn't matter?
    }else{
        printf("best matching != NULL\n");
        hop.interface = best_matching_route->outgoing_intf;
        hop.dst_ip = htonl(best_matching_route->next_hop_ip);
    }
    // free(best_matching_route);
    return hop;
}


/**
 * COPIED from dr_api.h
 * Handles the payload of a dynamic routing packet (e.g. a RIP or OSPF payload).
 *
 * @param ip   The IP address which the dynamic routing packet is from.
 *
 * @param intf The index of the interface on which the packet arrived.
 *
 * @param buf  This is the payload of a packet in for the dynamic routing
 *             protocol.  The caller is reponsible for managing the memory
 *             associated with buf (e.g. this function will NOT free buf).
 *
 * @param len  The number of bytes in the payload.
 */
void safe_dr_handle_packet(uint32_t ip, unsigned intf,
                           char* buf /* borrowed */, unsigned len) {
    /* handle the dynamic routing payload in the buf buffer */
    if(LOOPDEBUG) printf("enterting handle packet method!\n");
   
    uint32_t ip_host = ntohl(ip);

    // correspond to the 3.9 input processing section in the protocol description
    if((!validate_packet((rip_header_t*)buf, ip_host, intf))||(((rip_header_t*)buf)->command!=RIP_COMMAND_RESPONSE)){
        // invalid packet or not reponse message, ignore

        return;
    }else{
        int update_flag = 0;
        // start handling valid response message

        rip_header_t* rip_header = (rip_header_t*) buf;

        int entry_counter = ((int)len - 4)/20;

        for (int i = 0; i < entry_counter; i++){
            // two checks for each entry, according to the protocol specification
            // 1. is the destination address valid (eg. unicast, not net 0 or 127)
            // 2. is the metric valid (i.e. between 1 and 16, inclusive)
            // if any check fails, ignore that entry and proceed to the next
            rip_entry_t entry = rip_header->entries[i];
            // 1. check ip
            uint32_t ip_host = ntohl(entry.ip);
            // if (ip_host)

            // 2. check cost
            uint32_t cost_host = ntohl(entry.metric);
            if(cost_host>INFINITY || cost_host<1){
                continue; //go to the next entry
            }

            // now the entry is valid, we use the entry to update the corresponding cost to the destination

            // first get the cost of routing from thie router to the coming router(in the neighbor list)
            route_t* traverse_list = neighbors_first;
            route_t* exact_match_route = NULL;
            uint32_t cost = -1;
            while(traverse_list!=NULL){
                uint32_t mask = traverse_list->mask;
                if((ip_host & mask)==(traverse_list->subnet & mask)){
                    // if the subnet ip matches
                    if(traverse_list->outgoing_intf == (uint32_t)intf){
                        // if the interface id match
                        if(traverse_list->next_hop_ip == 0){
                            // according to readme, directly connected to that subnet
                            cost = traverse_list->cost;
                        }
                    }
                }
            }
            if(cost == (uint32_t)-1)  continue;

            if(entry.metric + cost >= INFINITY){
                entry.metric = INFINITY;
            }else{
                entry.metric = entry.metric + cost;
            }

            traverse_list = forward_table_first;
            // now we have checked the this comming route entry and it's connectivity with the neighbor list
            // we start traverse the forward table and try to get the shortest route and combine them
            // notice that this already included the case that an indirect route to neighbor is actually shorter
            // but we still have to do case distinction for entry insertion if it is the first time appears

            while(traverse_list!=NULL){
                uint32_t mask = traverse_list->mask;
                if((ip_host & mask)==(traverse_list->subnet & mask)){
                    // if the masked ip matches
                    if (mask == entry.subnet_mask){
                        exact_match_route = traverse_list;
                        break;
                    }
                }
            }

            struct timeval now;
            gettimeofday(&now, NULL);
           

            // general case 1: found a match

            if(exact_match_route!=NULL)
            { //need to update the forward table (if shorter route)
                // protocol page 27 bottom.
                if(exact_match_route->next_hop_ip == ip_host){
                    if(exact_match_route->cost != entry.metric){
                        // this can be due to some change in the sub route, (like break done in some links)
                        //  so we don't compare the distance
                        exact_match_route->cost = entry.metric;
                    }
                    // reintialize timeout
                    exact_match_route->last_updated = now;
                    update_flag = 1;
                }else{
                    //the coming entry is not heading towards this router
                    // then we only update when there is a smaller distance route
                    if(exact_match_route->cost > entry.metric){
                        // we only need to update the time, and cost
                        exact_match_route->last_updated = now;
                        exact_match_route->cost = entry.metric;
                        update_flag = 1;
                    }
                }
            }else
            { // didn't find a exact match route, need to insert in the forward table
                exact_match_route->subnet = entry.ip;
                exact_match_route->is_garbage = 0; //don't have to implement
                exact_match_route->last_updated = now;
                exact_match_route->mask = entry.subnet_mask;
                exact_match_route->next_hop_ip = entry.ip;
                exact_match_route->outgoing_intf = (uint32_t) intf;
                // simply add, so no need for comparison of cost
                exact_match_route->cost = entry.metric;

                // now insert into the forward list (!!not into neighbor list)
                route_t* old_first = forward_table_first;
                exact_match_route->next = old_first;
                forward_table_first = exact_match_route;

                update_flag = 1;
            }
        }


        // finished updating forward list, advertise it 
        // we only advertise when necessary, as the protocal states this can avoid bouncy routes
        if(update_flag) advertise_to_neighbors((int)dr_interface_count());
        if(LOOPDEBUG) printf("*********printing full forward table*********\n");
        if(LOOPDEBUG) print_routing_table(forward_table_first);
        if(LOOPDEBUG) printf("*********printing neighbor table*********\n");
        if(LOOPDEBUG) print_routing_table(neighbors_first);
    }


        if(LOOPDEBUG) printf("exiting handle packet method!\n");
}


/**
 * This method is called at a regular interval by a thread initialied by
 * dr_init.
 */
void safe_dr_handle_periodic() {
    /* handle periodic tasks for dynamic routing here */
    // From the RFC document
//    - Periodically, send a routing update to every neighbor.  The update
//      is a set of messages that contain all of the information from the
//      routing table.  It contains an entry for each destination, with the
//      distance shown to that destination.
    if(LOOPDEBUG) printf("enterting periodic method!\n"); 
    if(LOOPDEBUG) print_routing_table(forward_table_first);
    clean_neighbor_list(neighbors_first);
    clean_forward_list(forward_table_first);



    long update_time_diff = get_time() - last_updated_time;
    if(update_time_diff >= RIP_ADVERT_INTERVAL_SEC * 1000){ // in milli second
        last_updated_time = get_time();
        advertise_to_neighbors((int)dr_interface_count());
    }

        print_routing_table(forward_table_first);
        if(LOOPDEBUG)  printf("exiting periodic method!\n");
}

/**
 * COPIED FROM dr_api.h
 * This method is called when an interface is brought up or down and/or if its
 * cost is changed.
 *
 * @param intf             the index of the interface whose state has changed
 * @param state_changed    boolean; non-zero if the intf was brought up or down
 * @param cost_changed     boolean; non-zero if the cost was changed)
 */

static void safe_dr_interface_changed(unsigned intf,
                                      int state_changed,
                                      int cost_changed) {
    /* handle an interface going down or being brought up */
// case distinction:
// 1. interface brought up 
// 2. interface brought down
// 3. cost chaged
// 
    if(DEBUG) printf("enterting interface changed method!\n");
    lvns_interface_t interface = dr_get_interface(intf);
    uint32_t ip_host = ntohl(interface.ip);

    if(state_changed && dr_get_interface(intf).enabled){
        // interface is brought up 
        // we need to 1. add an entry into the forward table.but 
                            //  if there is a indirect route , to this new router, which is cheaper than this new link
                            //  then we only add this to neighbor list. otherwise we need to modify both list
        // first find lookup the interface.ip in this 
        
        route_t* existed_route = (route_t*)malloc(sizeof(route_t));
        route_t* new_route = (route_t*)malloc(sizeof(route_t));
        new_route->cost = interface.cost;
        new_route->is_garbage = 0;
        new_route->mask = ntohl(interface.subnet_mask);
        new_route->next_hop_ip = 0;
        new_route->outgoing_intf = (u_int32_t)intf;
        new_route->subnet = interface.ip;

        struct timeval t;
        t.tv_sec = -1; //neighboring link has TTL = -1
        t.tv_usec = 0; //dummy initialization, will be filled by gettimeofday
        new_route->last_updated = t;

        if(check_ip_in_list_return_route(forward_table_first, ip_host, existed_route)){ //such route exist
            uint32_t existed_cost=existed_route -> cost; //must be an indirect route. since this is a new interface
            if(existed_cost < interface.cost){
                // then only add it into the neighbor list
                route_t* neighbor_first_old = neighbors_first;
                new_route->next = neighbor_first_old;
                neighbors_first = new_route; 
            }else{
                //replace the one in forward list, and also add new route to neighbor list
                // we do this operation by, replacing all information, other than next pointer
                restore_route_from_neighbor_list(new_route , existed_route);
                // and push it into the neighbor list 
                route_t* neighbor_first_old = neighbors_first;
                new_route->next = neighbor_first_old;
                neighbors_first = new_route; 
            }
        }else{ //such route does not exist, add it to both lists
                route_t* neighbor_first_old = neighbors_first;
                new_route->next = neighbor_first_old;
                neighbors_first = new_route; 

                route_t* copy_new_route = (route_t*)malloc(sizeof(route_t));
                memcpy(new_route, copy_new_route, sizeof(*new_route));
                route_t* forward_first_old = forward_table_first;
                copy_new_route->next = forward_first_old;
                forward_table_first = copy_new_route;
        }

    }else if (state_changed && !dr_get_interface(intf).enabled){
        // this interface is brought down.
        // notice we should delete the corresponding entry in the neighbor list.
        // and if in the forward list, the route to that router is a direct one, we delete it,
        // otherwise we keep it.

        // first we handle the direct table
        route_t* to_delete_route = (route_t*)malloc(sizeof(route_t));
        if(check_ip_in_list_return_route(neighbors_first, ip_host, to_delete_route)){
            to_delete_route->cost = INFINITY;
            clean_neighbor_list(neighbors_first); //can also use this method to clean neighbor list
        }else{
            printf("ERROR\n");
        }

        // now check in the forward list, delete all entries, which entry->outgoing_intf = intf
        route_t* curr_route = forward_table_first;
        while(forward_table_first!=NULL){
            if(curr_route->outgoing_intf == (uint32_t)intf){
                curr_route->cost = INFINITY;
            }
            curr_route = curr_route->next;
        }

        // clean the table
        clean_forward_list(forward_table_first);
        free(to_delete_route);
    }else if (cost_changed && dr_get_interface(intf).enabled){
        // modify all affected routes in both lists

        // we first handle the neighbor list. neighbor list's corresponding entry will be changed anyways.
        // no matter the actually route is shorter or not
        if (interface.cost > INFINITY) interface.cost = INFINITY;

        int old_cost_saved = 0;
        route_t* to_modify_route = (route_t*)malloc(sizeof(route_t));
        if(check_ip_in_list_return_route(neighbors_first, ip_host, to_modify_route)){   
            old_cost_saved = to_modify_route->cost;
            to_modify_route->cost = interface.cost;
            clean_neighbor_list(neighbors_first); //can also use this method to clean neighbor list
        }else{
            printf("ERROR\n");
        }

        //we then check the forward list.
        // check all routes going out from this interface, and assign new cost. we know this might not be 
        // shortest anymore, but the further update will be handled by handle response 
        route_t* curr_route = forward_table_first;
        while(curr_route!=NULL){
            if(curr_route->outgoing_intf == intf){
                curr_route->cost = curr_route->cost - old_cost_saved + interface.cost;
            }
            // we also need check if now, the new indirect cost is somehow larger than a direct connection
            // for connecting neighbor!
            // if so replace it.
            // check neighbor list.
            route_t *neighbor_indirect_route = (route_t*)malloc(sizeof(route_t));
            if(check_ip_in_list_return_route(neighbors_first, curr_route->subnet, neighbor_indirect_route)){   
                if(curr_route->cost > interface.cost){
                    // bc the neighbor list is already refreshed, so safe to use this function to 
                    // "restore" from neighbor list
                    restore_route_from_neighbor_list(neighbor_indirect_route, curr_route);
                }   
            }



            curr_route = curr_route->next;
        }



        free(to_modify_route);
    }

    advertise_to_neighbors((int)dr_interface_count());

        if(DEBUG){
            printf("*********printing full forward table*********\n");
            print_routing_table(forward_table_first);
            printf("*********printing neighbor table*********\n");
            print_routing_table(neighbors_first);
        }


        if(DEBUG) printf("exiting interface changed method!\n");
}

/* definition of internal functions */

// gives current time in milliseconds
long get_time(){
    // Now in milliseconds
    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec * 1000 + now.tv_usec / 1000;
}

// prints an ip address in the correct format
// this function is taken from: 
// https://stackoverflow.com/questions/1680365/integer-to-ip-address-c 
void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

// prints the full routing table
void print_routing_table(route_t *head){
    // printf("==================================================================\nROUTING TABLE:\n==================================================================\n");
    int counter = 0;
    route_t *current = head;
    while (current != NULL){
        printf("Entry %d:\n",counter);
        printf("\tSubnet: ");
        print_ip(current->subnet);
        printf("\tMask: ");
        print_ip(current->mask);
        printf("\tNext hop ip: ");
        print_ip(current->next_hop_ip);
        printf("\tOutgoing interface: ");
        print_ip(current->outgoing_intf);
        printf("\tCost: %d\n", current->cost);
        printf("\tLast updated (timestamp in microseconds): %li \n", current->last_updated.tv_usec);
        // printf("==============================\n");
        counter ++;

        current = current->next;
    }
}


void advertise_to_neighbors(int num_interfaces){
    // first we get how many entires are there in the forward table
    int route_entry_counter = 0;
    route_t* route_entry_temp = forward_table_first;
    while(route_entry_temp!= NULL){
        route_entry_counter ++;
        route_entry_temp = route_entry_temp->next;
    }
    for (int i = 0; i < num_interfaces;i++){
        lvns_interface_t curr_if = dr_get_interface(i);
        int valid_interface = (curr_if.cost < 16) && (curr_if.enabled);
        if(valid_interface){
            // create an update information and send, for this i-th interface
            // each packet contains: RIP header (size = 4), forward table (entry_counter * sizeof(entry)) 
            // char* payload_header = (char*)malloc(4 + 20*entry_counter);
            rip_header_t* payload_header = (rip_header_t*)malloc(4 + 20*route_entry_counter);
            // now start making the RIP advertisement packet
            //     typedef struct rip_header_t {
            //     char        command;
            //     char        version;
            //     uint16_t    pad;        /* just put zero in this field */
            //     rip_entry_t entries[0];
            // } __attribute__ ((packed)) rip_header_t;
            payload_header->pad = (uint16_t) 0;
            payload_header->version = RIP_VERSION;
            // regular update, so response messages
            payload_header->command = RIP_COMMAND_RESPONSE;
            // typedef struct rip_entry_t {
            //     uint16_t addr_family;
            //     uint16_t pad;           /* just put zero in this field */
            //     uint32_t ip;
            //     uint32_t subnet_mask;
            //     uint32_t next_hop;
            //     uint32_t metric;
            // } __attribute__ ((packed)) rip_entry_t;
            route_t* curr_route_entry = forward_table_first;
            for(int j = 0; j < route_entry_counter; j++){
                // initialize entries
                payload_header->entries[j].addr_family = (uint16_t)RIP_VERSION;
                payload_header->entries[j].pad = (uint16_t) 0;
                payload_header->entries[j].ip = ntohl(curr_route_entry->subnet);
                payload_header->entries[j].subnet_mask = ntohl(curr_route_entry->mask);
                payload_header->entries[j].next_hop = ntohl(curr_route_entry->next_hop_ip);
                
                // handling split horizon with poison reverse
                route_t* targetRoute = (route_t*)malloc(sizeof(route_t));

                // checking if this route's next hop, is the neighbor I am broadcasting to
                int in_neighbor_list = check_ip_in_list(neighbors_first, curr_route_entry->next_hop_ip);
                if((i == (int)curr_route_entry->outgoing_intf) && in_neighbor_list){
                    payload_header->entries[j].metric = INFINITY;
                }else{
                    payload_header->entries[j].metric = (uint32_t) curr_route_entry->cost;
                }
                free(targetRoute);
                // finished initialization
                curr_route_entry = curr_route_entry->next;
            }
            // advertise(send) the payload
            // i_th interface
            dr_send_payload(RIP_IP,RIP_IP, i, (char*)payload_header, 4 + 20*route_entry_counter);

            free(payload_header);
        }
    }
}

route_t* longest_match_prefix_route(route_t* forward_list_starting, uint32_t targetIP, route_t* targetRoute){
    targetRoute = NULL;
    route_t* route_temp;
    print_routing_table(forward_list_starting);

    route_temp = forward_list_starting;
    uint32_t longest_mask = 0;
    while(route_temp!=NULL){
        // the principle is, when the masked ip equals to masked subnet, 
        // AND this mask is longer, than any previous mask, we do one update
        print_ip(targetIP);
        print_ip(route_temp->subnet);
        if((targetIP & route_temp->mask) == (route_temp->subnet & route_temp->mask)){
            if(longest_mask < (uint32_t)(route_temp->mask)){
                targetRoute = route_temp;
                longest_mask = (uint32_t)(route_temp->mask);
                printf("best mask found so far: \n");
                print_ip(longest_mask);
            }
        }
        route_temp = route_temp->next;
    }
    // free(route_temp);
    return targetRoute;
}

// TODO check pointer if corrct?  the free method
int check_ip_in_list(route_t* list, uint32_t targetIP){
    route_t* route_temp;
    route_temp = list;
    while(route_temp!=NULL){
        if((targetIP & route_temp->mask) == (route_temp->subnet & route_temp->mask)){
            // free(route_temp);
            return 1;
        }
        route_temp = route_temp->next;
    }
    // free(route_temp);
    return 0;
}
int check_ip_in_list_return_route(route_t* list, uint32_t targetIP, route_t* targetRoute){
    route_t* route_temp;
    route_temp = list;
    while(route_temp!=NULL){
        if((targetIP & route_temp->mask) == (route_temp->subnet & route_temp->mask)){
            *targetRoute = *route_temp;
            // free(route_temp);
            return 1;
        }
        route_temp = route_temp->next;
    }
    // free(route_temp);
    return 0;
}


// implemented according protocol page 26, section 3.9.2
int validate_packet(rip_header_t* rip_header, uint32_t ip_host, unsigned interface){
    //1. The Response must be ignored if it is not from the RIP port
    // comment: this trivialy hold in our setting
    //2. The datagram's ipv4 source address should be checked tosee whether the datagram is 
    // from a valid neighbor
    if(!check_ip_in_list(neighbors_first, ip_host)){
        return 0;
    }

    //3. check if the response is from one of the router's own address
    //TODO  how?



    return 1;
}

// traverse the list and clean up unreachable destinations and expired entries
// WARNING!! if you delete an neighbor route, we need to restore it in the forward table.
// otherwise it will think there is no route between expired neighbors. 
void clean_forward_list(route_t* route_list_first){
    route_t* curr_route = route_list_first;
    route_t* prev_route = NULL;
    while(curr_route!=NULL){
printf("EEEE \n");
        int to_delete_flag = 0;
        long route_last_update = (curr_route->last_updated.tv_usec)+curr_route->last_updated.tv_sec*1000;
        long curr_time = get_time();
        // timeout
        if (DEBUG){
            printf("CLEAN UP CLEANUP !\n");
            printf("print forward table\n");
            print_routing_table(forward_table_first);
            printf("print neighbor table\n");
            print_routing_table(neighbors_first);
            // printf("route_last_update = %ld \n", route_last_update);
        }
        //timeout
        if(curr_time - route_last_update >= RIP_TIMEOUT_SEC*1000 && route_last_update!=1000) to_delete_flag = 1;
        // unreachable
        if(curr_route->cost >= INFINITY) to_delete_flag = 1;
        if(to_delete_flag){
            route_t* temp_to_delete = curr_route;
            // first we check if the route is a dirrect route, is yes we restore its default value (from neighbor list)
            route_t* traverse_list = neighbors_first; 
            route_t* exact_match_route = NULL;

// printf("AAAA \n");
            while(traverse_list!=NULL){
                uint32_t mask = traverse_list->mask;
                if((temp_to_delete->subnet & mask)==(traverse_list->subnet & mask)){
                    // if the masked ip matches
                    if (mask == temp_to_delete->mask){
                        exact_match_route = traverse_list;
                        break;
                    }
                }
                traverse_list = traverse_list->next;
            }

printf("BBBB \n");
            print_ip(curr_route->subnet);
            // exact match route is in neighbor list!
            if(exact_match_route != NULL && exact_match_route->cost<INFINITY){ // we got a match, have to restore
                restore_route_from_neighbor_list(exact_match_route, curr_route);
                // printf("FFFF \n");
                // no need to delete ,thus jump the free part
                curr_route = curr_route->next;
                continue;
            }else{ //simply delete
                if(prev_route==NULL){//this indicate that curr_route is the first of the list,
                // thus we set the new first as the next route
printf("QQQQ \n");
// print_ip(curr_route->subnet);
                    forward_table_first = curr_route->next;
                    prev_route = NULL; //previous_route still NULL
                }else{
printf("wwww \n");
                    // set the prev_route->next to the next route. jump the current one
                    prev_route->next = curr_route->next;
                    // and do not update the previous route, since it will still be the same one in next iteration
                }
            }
            curr_route = curr_route->next;
            // *******************TODO , double check this free!!!***********************
            free(temp_to_delete);  //purpose is to free the useless route to save memory space
            // *******************TODO , double check this free!!!***********************
        }else{ //no deletion happens
        printf("CCCC \n");
            prev_route = curr_route;
            curr_route = curr_route->next;
        }
        printf("EXIT? \n");
    }
            printf("EXITing \n");
                    if (DEBUG){
            printf("CLEAN UP CLEANUP !\n");
            printf("print forward table\n");
            print_routing_table(forward_table_first);
            printf("print neighbor table\n");
            print_routing_table(neighbors_first);
            // printf("route_last_update = %ld \n", route_last_update);
        }
                    printf("EXIT \n");
}

void restore_route_from_neighbor_list(route_t* neighbor_list_route, route_t* forward_list_route){
    forward_list_route->cost = neighbor_list_route->cost;
    forward_list_route->is_garbage = neighbor_list_route->is_garbage;
    forward_list_route->last_updated = neighbor_list_route->last_updated;
    forward_list_route->mask = neighbor_list_route->mask;
    // forward_list_route->next
    forward_list_route->next_hop_ip = neighbor_list_route->next_hop_ip;
    forward_list_route->outgoing_intf = neighbor_list_route->outgoing_intf;
    forward_list_route->subnet = neighbor_list_route->subnet;
}

void clean_neighbor_list(route_t* list_first){
    // we traverse the neighbor list, it's simple. just delete all unreachable routes, since neighbor list
    // doesn't have timeout issue.
    route_t* curr_route = list_first;
    route_t* prev_route = NULL;
    printf("Clean up neighbor list\n");
    
    while(curr_route!=NULL){
        route_t* to_delete_route = curr_route;
        if(curr_route->cost>=INFINITY){
            if(prev_route == NULL){
                printf("deleting AAAAA\n");
                // the to delete route is the first in the list     
                curr_route = curr_route->next;
                neighbors_first = curr_route;
                // free(to_delete_route);
                continue;
            }else{
                printf("deleting BBBBB\n");
                prev_route->next = curr_route->next;
                curr_route = curr_route->next;
                // free(to_delete_route);
                continue;
            }
        }else{
            // reachable route, simply go to the next
            printf("nothing happened \n");
            prev_route = curr_route;
            curr_route = curr_route->next;
        }
    }
}