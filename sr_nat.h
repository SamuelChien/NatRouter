
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
    nat_trans_int_to_ext,
    nat_trans_ext_to_int
} sr_nat_trans_type;

typedef enum {
    tcp_state_listen,
    tcp_state_syn_sent,
    tcp_state_syn_recv,
    tcp_state_established,
    tcp_state_fin_wait1,
    tcp_state_fin_wait2,
    tcp_state_close_wait,
    tcp_state_time_wait,
    tcp_state_last_ack,
    tcp_state_closed
} sr_tcp_state;


struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip_src;
  uint16_t src_seq;
  uint32_t ip_dest;
  uint16_t port_dest;
  time_t last_updated;
  sr_tcp_state state;

  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  unsigned int icmpTimeout;
  unsigned int tcpEstTimeout;
  unsigned int tcpTransTimeout;
  unsigned int activated;
  uint32_t auxCounter; /* used to generate source port/ID */
  uint32_t nat_external_ip;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

uint32_t sr_nat_genAux(struct sr_nat *nat);

void print_nat_mappings(struct sr_nat *nat);

struct sr_nat_connection* 
sr_nat_lookup_connection(struct sr_nat* nat, struct sr_nat_mapping* mapping, 
  uint32_t ip_src, uint32_t ip_dest, uint32_t src_seq, uint16_t port_dest);

#endif
