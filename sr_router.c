/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"
#include "sr_utils.h"
/*
 * Author: Tzu-Yao Chien 998758759
 *		   Pouria Shirasb 995475622
 */
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 truct in_addr routingDest*
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));
    sr_nat_init(&(sr->nat));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacketsr_print_routing_table(sr);(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface); 

	/* Initialize NAT external IP if it is not already */
    if(sr->nat.activated && sr->nat.nat_external_ip == 0)
    {
        struct sr_if* natExternalInterface = sr_get_interface(sr, NAT_EXT);
        sr->nat.nat_external_ip = natExternalInterface->ip;
    }
    
    print_hdrs(packet,len);


    printf("*** -> Received packet of length %d \n",len);
    /*Ethernet Sanity Check*/
    /* Check 1: length must at least the size of ethernet header*/
    int minlength = sizeof(sr_ethernet_hdr_t);
    if (len < minlength) 
    {
        fprintf(stderr, "sr_handlepacket: insufficient length\n");
        return;
    }
    if(len > 1514)
    {
        fprintf(stderr, "sr_handlepacket: length over Ethernet MTU\n");
        return;
    }
    /*Check 2: destination MAC address must be server or broadcast*/
    int matchingHeaderAddr 	= 1;
    int broadcastAddr 		= 1;
    sr_ethernet_hdr_t *ehdr 	= (sr_ethernet_hdr_t *)packet;
    uint8_t *addr = ehdr->ether_dhost;
    /*Get the interface's MAC address*/
    struct sr_if* srcInterface = sr_get_interface(sr, interface);
    if(srcInterface == NULL)
    {
        fprintf(stderr,"sr_handlepacket: Failed to pass ETHERNET header sanity check due to bad interface name\n");
        return;
    }
    uint8_t *interfaceAddr = srcInterface->addr;
    /*Compare destination address with broadcast address and interface mac address*/  
    int pos = 0;
    uint8_t cur;
    for (; pos < ETHER_ADDR_LEN; pos++) {
        cur = addr[pos];
        /*Check is IP a broadcast IP gets broadcast*/
        if(cur != 255)
        {
            broadcastAddr = 0;
        }
        /*The message is sent */
        if(cur != interfaceAddr[pos])
        {
            matchingHeaderAddr = 0;  
        }
    }  
    if(!matchingHeaderAddr && !broadcastAddr)
    {
        fprintf(stderr,"sr_handlepacket: Failed to pass ETHERNET header sanity check due to bad destination header address\n");
        return;
    }

    /*check ethernet type*/
    uint16_t ethtype = ethertype(packet);
    /* IP packet*/
    if(ethtype == ethertype_ip)
    {
        /*Sanity Check ARP Packet*/
        /*Check 1: length*/
        minlength += sizeof(sr_ip_hdr_t);
        if (len < minlength) {
            fprintf(stderr, "sr_handlepacket: insufficient length\n");
            return;
        }

        sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        /*Check 2: checksum*/
        int originalChecksum = iphdr->ip_sum;
        iphdr->ip_sum = 0x0000;
        int calculatedChecksum = cksum((packet + sizeof(sr_ethernet_hdr_t)),(iphdr->ip_hl * 4));
        if(originalChecksum != calculatedChecksum)
        {
            fprintf(stderr,"sr_handlepacket: IP header checksum does not match: %i\n",calculatedChecksum);
            return;
        }
        iphdr->ip_sum = originalChecksum;

        /*Check Dest IP*/
        uint32_t destIP = iphdr->ip_dst;
        uint32_t ip_proto = iphdr->ip_p;
        struct sr_if* dest_if = sr_find_interface(sr,destIP);
        char* destInterface = dest_if->name;
 
        /*The packet is sending to router*/
        if(destInterface) /* is there an interface that has destIP ? */
        {
            /* NAT enabled ? */
            if(sr->nat.activated)
            {
                /* External to External */
                if(!strcmp(interface,NAT_EXT) && !strcmp(destInterface,NAT_EXT))
                {
                    printf("Ext:%s -> Ext:%s\n",interface,destInterface);
                    print_nat_mappings(&sr->nat);
                    sr_nat_mapping_type mapping_type;
                    uint16_t aux_ext;
                    /* is it an ICMP packet ? */
                    if(ip_proto == ip_protocol_icmp)
                    {
                        /* Check length */
                        minlength += sizeof(sr_icmp_hdr_t);
                        if (len < minlength)
                        {
                            fprintf(stderr, "sr_handlepacket: insufficient length\n");
                            return;            
                        }

                        sr_icmp_t3_hdr_t *icmphdr = (sr_icmp_t3_hdr_t*) (packet + 
                                sizeof(sr_ethernet_hdr_t) + 
                                sizeof(sr_ip_hdr_t));

                        originalChecksum = icmphdr->icmp_sum;
                        icmphdr->icmp_sum = 0;
                        calculatedChecksum = cksum(icmphdr,ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));
                        icmphdr->icmp_sum = originalChecksum;

                        /* Verify Checksum */       
                        if(originalChecksum != calculatedChecksum)
                        {
                            fprintf(stderr, "sr_handlepacket: ICMP checksum does not match\n");
                            return;
                        }
                        mapping_type = nat_mapping_icmp;
                        aux_ext = icmphdr->unused;

                    }
                    else if(ip_proto == ip_protocol_tcp)
                    {
                        minlength += sizeof(sr_tcp_hdr_t);
                        if (len < minlength)
                        {
                            fprintf(stderr, "sr_handlepacket: insufficient length for tcp packet\n");
                            return;
                        }
                        sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t*) (packet +
                                sizeof(sr_ethernet_hdr_t) +
                                sizeof(sr_ip_hdr_t));
                        printf("\n************************DUMP OUT CURRENT TCPHDR***************************\n");
                        printf("SRC_PORT: %i\n", tcphdr->src_port);
                        printf("DEST_PORT: %i\n", tcphdr->dest_port);
                        printf("SeqNum: %i\n", tcphdr->sequence_num);
                        printf("ACK: %i\n", tcphdr->ack_num);
                        printf("FLAG: %i\n", tcphdr->flag_state);
                        printf("CHECKSUM: %i\n", tcphdr->checksum);
                        printf("\n************************FINISH DUMPING************************************\n");

                        /* Verify Checksum */
                        if(tcp_cksum(packet,len) != tcphdr->checksum)
                        {
                            fprintf(stderr, "sr_handlepacket: tcp checksum does not match\n");
                            return;
                        }

                        aux_ext = tcphdr->dest_port;
                        mapping_type = nat_mapping_tcp;
                    }
                    printf("AUX-----------%i\n",aux_ext);
                    struct sr_nat_mapping *mapping = sr_nat_lookup_external(&(sr->nat),aux_ext, mapping_type);

                    if(mapping)
                    {
                        printf("Translating External to internal\n");
                        sr_nat_translate(sr,packet,len, mapping, nat_trans_ext_to_int);
                        sr_handlepacket(sr,packet,len, NAT_INT);
                        free(mapping);
                        return;
                    }
                    else
                    {
                        printf("Problem wit external looking for mapping\n");
                    }
                }
                /* Internal to Internal */
                else if(!strcmp(interface,NAT_INT) && !strcmp(destInterface,NAT_INT))
                {
                    printf("Int:%s -> Int:%s\n",interface,destInterface);
                }   
                /* Internal to External / External to Internal */
                else 
                {   
                    printf("Int/Ext:%s -> Ext/Int:%s\n",interface,destInterface);
                    /* Send ICMP Net Unreachable */
                    sr_send_icmp(sr,packet,len,3,0,interface);
                }
            }

            printf("PACKET FOR ROUTER ITSELF\n");

            /* is it an ICMP packet ? */
            if(ip_proto == ip_protocol_icmp)
            {

                /* Check length */
                minlength += sizeof(sr_icmp_hdr_t);
                if (len < minlength)
                {
                    fprintf(stderr, "sr_handlepacket: insufficient length\n");
                    return;            
                }

                sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t*) (packet + 
                        sizeof(sr_ethernet_hdr_t) + 
                        sizeof(sr_ip_hdr_t));
                originalChecksum = icmphdr->icmp_sum;
                icmphdr->icmp_sum = 0;
                calculatedChecksum = cksum(icmphdr,ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));
                icmphdr->icmp_sum = originalChecksum;

                /* Verify Checksum */       
                if(originalChecksum != calculatedChecksum){
                    fprintf(stderr, "sr_handlepacket: ICMP checksum does not match\n");
                    /*return;*/
                }


                /* Is it an ICMP Echo Request ? */
                if(icmphdr->icmp_type == 8)
                {
                    if(icmphdr->icmp_code != 0)
                    {
                        fprintf(stderr,"sr_handlepacket: bad icmp code\n");
                        return;
                    }

                    /* Send ICMP Type 0 */
                    sr_send_icmp(sr,packet,len,0,0,interface);

                }
                /* ignore otherwise */
                else
                {
                    fprintf(stderr,"sr_handlepacket: Unexpected ICMP packet %d\n",icmphdr->icmp_type);
                    return;
                }

            }
            /* is it a TCP/UDP packet ? */
            else if(ip_proto == ip_protocol_tcp || ip_proto == ip_protocol_udp)
            {
                /* Send ICMP port unreachable */
                sr_send_icmp(sr,packet,len,3,3,interface);
            }
            /* if it is anything else, ignore it */
            else{
                fprintf(stderr,"sr_handlepacket: Unrecognized protocol");
                return;
            }
        }
        else
        {
            /*PACKET FORWARDING, DESTINATION IS NOT ROUTER*/
            /*Sanity Check 1: see if we have the destination address in router, if not then sent ICMP*/
            if(sr->routing_table == 0)
            {
                fprintf(stderr, "IP Packet Forwarding Sanity Check Fail due to empty routing table\n");

                /* Send ICMP Net Unreachable */
                sr_send_icmp(sr,packet,len,3,0,interface);
                return;
            }

            char* rInterface = sr_rtable_lookup(sr, destIP);
            if(rInterface == NULL)
            {
                fprintf(stderr,"IP Forwarding Sanity Check fail due to no matching interface in routing table\n");
                /* Send ICMP Net Unreachable */
                sr_send_icmp(sr,packet,len,3,0,interface);
                return;
            }
            /*check 2: see if TTL is valid, if not sent ICMP*/
            if(iphdr->ip_ttl < 2)
            {
                fprintf(stderr,"IP Forwarding Sanity Check fails due to less than 2 TTL\n");
                /*Sent ICMP Packet: Time Exceeded*/
                sr_send_icmp(sr,packet,len,11,0,interface);
                return;
            }

            if(sr->nat.activated)
            {
                /*find internal interface name by src ip*/
                if (strcmp(interface, NAT_INT) == 0 && strcmp(rInterface, NAT_EXT) == 0)
                {

                    sr_nat_mapping_type proto_type;
                    uint16_t sourcePort = 0;
                    struct sr_nat_connection* initialConnection = NULL;
                    if(ip_proto == ip_protocol_icmp)
                    {
                        /*handle forward icmp while getting icmp id*/
                        /* Check length */
                        minlength += sizeof(sr_icmp_t3_hdr_t);
                        if (len < minlength)
                        {
                            fprintf(stderr, "sr_handlepacket: insufficient length\n");
                            return;            
                        }

                        sr_icmp_t3_hdr_t *icmphdr = (sr_icmp_t3_hdr_t*) (packet + 
                                sizeof(sr_ethernet_hdr_t) + 
                                sizeof(sr_ip_hdr_t));
                        originalChecksum = icmphdr->icmp_sum;
                        icmphdr->icmp_sum = 0;
                        calculatedChecksum = cksum(icmphdr,ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));
                        icmphdr->icmp_sum = originalChecksum;

                        /* Verify Checksum */       
                        if(originalChecksum != calculatedChecksum)
                        {
                            fprintf(stderr, "sr_handlepacket: ICMP checksum does not match\n");
                            return;
                        }
                        sourcePort = icmphdr->unused;
                        proto_type = nat_mapping_icmp;
                        printf("ICMP Checksum Works, new sourcePort %i\n", sourcePort);
                    }
                    else if(ip_proto == ip_protocol_tcp)
                    {

                        minlength += sizeof(sr_tcp_hdr_t);
                        if (len < minlength)
                        {
                            fprintf(stderr, "sr_handlepacket: insufficient length for tcp packet\n");
                            return;            
                        }

                        sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t*) (packet + 
                                sizeof(sr_ethernet_hdr_t) + 
                                sizeof(sr_ip_hdr_t));
                        printf("\n************************DUMP OUT CURRENT TCPHDR***************************\n");			
                        printf("SRC_PORT: %i\n", tcphdr->src_port);
                        printf("DEST_PORT: %i\n", tcphdr->dest_port);
                        printf("SeqNum: %i\n", tcphdr->sequence_num);
                        printf("ACK: %i\n", tcphdr->ack_num);
                        printf("FLAG: %i\n", tcphdr->flag_state);
                        printf("CHECKSUM: %i\n", tcphdr->checksum);
                        printf("\n************************FINISH DUMPING************************************\n");

                        /* Verify Checksum */       
                        if(tcp_cksum(packet,len) != tcphdr->checksum)
                        {
                            fprintf(stderr, "sr_handlepacket: tcp checksum does not match\n");
                            return;
                        }
                        sourcePort = tcphdr->src_port;
                        proto_type = nat_mapping_tcp;
                        printf("TCP checksum works, new sourcePort %i\n", sourcePort);
                        struct sr_nat_connection* initialConnection = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
                        printf("****************************INSERT NEW CONNECTION IN HANDLE PACKET*****************\n");
                        initialConnection->ip_src = iphdr->ip_src;
                        initialConnection->src_seq = tcphdr->sequence_num;
                        initialConnection->ip_dest = iphdr->ip_dst;
                        initialConnection->port_dest = tcphdr->dest_port;
                        initialConnection->last_updated = time(NULL);
                        initialConnection->state = tcp_state_syn_sent;
                        printf("IP SRC: %i\n Port SRC %i\n IP DEST %i\n PORT DEST %i\n DATE %i\n STATE %i", initialConnection->ip_src, initialConnection->src_seq, initialConnection->ip_dest, initialConnection->port_dest, initialConnection->last_updated, initialConnection->state);
                        printf("*********************************FINISH INSERTING CONNECTION IN HANDLE PACKET*************\n");
                    }

                    struct sr_nat_mapping *internal_mapping = sr_nat_lookup_internal(&sr->nat, iphdr->ip_src, sourcePort, proto_type); 
                    if(internal_mapping == NULL)
                    {
			printf("Internal Mapping is empty, Need to create a new one with sourcePort %i\n", sourcePort);
                        internal_mapping = sr_nat_insert_mapping(&sr->nat, iphdr->ip_src, sourcePort, proto_type);
                        if(proto_type == nat_mapping_tcp)
                        {
                            internal_mapping->conns = initialConnection;
                        }
			/*In case of free the instance*/
			internal_mapping = sr_nat_lookup_internal(&sr->nat, iphdr->ip_src, sourcePort, proto_type);
			printf("source port after insert %i\n", internal_mapping->aux_int);
                    }
                    fprintf(stderr, "\n************ TRANSLATE INTERNAL MESSAGE TO EXTERNAL *************\n");
                    sr_nat_translate(sr,packet,len, internal_mapping, nat_trans_int_to_ext);
                    printf("SR_NAT_TRANS CALLED - INT TO EXT \n");
                    sr_handlepacket(sr,packet,len, NAT_EXT);

                    if(internal_mapping)
                    {
                        free(internal_mapping);
                    }
                    return;
                }
                else if (strcmp(interface, NAT_EXT) == 0 && strcmp(rInterface, NAT_INT) == 0)
                {
                    fprintf(stderr,"Cannot ping internal nat from external");
                    /* Send ICMP Net Unreachable */
                    sr_send_icmp(sr,packet,len,3,0,interface);
                    return;
                }
            }

            /*Find MAC address by look up requested destination IP in cache*/
            struct sr_arpentry* cacheEntry = sr_arpcache_lookup(&sr->cache, destIP);
            if(cacheEntry != NULL)
            {
                /* this might crush free(lookupResult);*/
                /*Now pack everything with new checksum and TTL and send */
                struct sr_if* curInterface = sr_get_interface(sr, rInterface);
                iphdr->ip_ttl -= 1;
                /*Calculate new checksum*/
                iphdr->ip_sum = 0;
                iphdr->ip_sum = cksum((packet + sizeof(sr_ethernet_hdr_t)),(iphdr->ip_hl*4));
                memcpy(ehdr->ether_shost, curInterface->addr, ETHER_ADDR_LEN);
                memcpy(ehdr->ether_dhost, cacheEntry->mac, ETHER_ADDR_LEN);
                /*dump it out and see*/
                sr_send_packet(sr, packet, len, rInterface);
                free(cacheEntry);
            }
            else
            {
                struct sr_arpreq* currentRequest = sr_arpcache_queuereq(&sr->cache, destIP, packet, len, interface);
                /*TODO Need to free sr_arpreq*/
            }
        }
    }
    /*ARP*/
    else if(ethtype == ethertype_arp)
    {
        /*Sanity check ARP packet*/
        minlength += sizeof(sr_arp_hdr_t);
        if (len < minlength)
        {
            fprintf(stderr,"sr_handlepacket: Failed to pass ARP header sanity check due to insufficient length\n");
            return;
        }
        sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        if(ntohs(arp_hdr->ar_op) == arp_op_request)
        {
            /*Save the src destination to cache*/
            unsigned char *srcMacAddr = arp_hdr->ar_sha;
            uint32_t srcIP = arp_hdr->ar_sip;
            sr_arpcache_insert(&sr->cache, srcMacAddr, srcIP);
            uint32_t destIP = arp_hdr->ar_tip;
            /*Check interface's IP with target IP*/
            uint32_t interfaceIP = srcInterface->ip;
            if(interfaceIP == destIP)
            {
                arp_hdr->ar_op  = htons(arp_op_reply);
                memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                arp_hdr->ar_tip = arp_hdr->ar_sip;
                memcpy(arp_hdr->ar_sha, srcInterface->addr, ETHER_ADDR_LEN);
                arp_hdr->ar_sip = interfaceIP;
                memcpy(ehdr->ether_shost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                memcpy(ehdr->ether_dhost, arp_hdr->ar_tha, ETHER_ADDR_LEN);
                /*dump it out and see*/
                sr_send_packet(sr, packet, len, interface);
            }
        }
        else if(ntohs(arp_hdr->ar_op) == arp_op_reply)
        {
            /*printf("ARP receive a reply\n");*/

            /*Add the reply to cache table*/
            unsigned char *srcMacAddr = arp_hdr->ar_sha;
            uint32_t srcIP = arp_hdr->ar_sip;
            /*sr_arpcache_dump(&sr->cache);*/

            /*Find the request in the sweep queue, and continue all waiting packet by calling handle packet*/
            struct sr_arpreq* request = sr_arpcache_insert(&sr->cache, srcMacAddr, srcIP);
            if(request == NULL)
            {
                fprintf(stderr,"sr_handlepacket: arprequest not found in queue\n");
            }
            else
            {
                /*printf("Request queue is not empty\n");*/
                struct sr_packet* package = request->packets;
                while(package)
                {
                    sr_handlepacket(sr, package->buf, package->len, package->iface);
                    package = package->next;
                }
                sr_arpreq_destroy(&sr->cache, request);
            }

        }
        else
        {
            fprintf(stderr,"sr_handlepacket: Failed due to bad arp option code: %d\n", ntohs(arp_hdr->ar_op));
            return;
        }
    }  
    /*Unknown*/
    else
    {
        fprintf(stderr,"Unrecognized Ethernet Type: %d\n", ethtype);
    }
}/* end sr_ForwardPacket */



/***********************************************************
 * Method: sr_rtable_lookup
 *
 * Params: 
 *       struct sr_instance *sr
 *      uint32_t destIP
 *
 * Description:
 *  Get Interface string by ip
 *
 **********************************************************/
char* sr_rtable_lookup(struct sr_instance *sr, uint32_t destIP){
    struct sr_rt* rTable = sr->routing_table;
    char* rInterface = NULL;
    uint32_t rMask = 0;
    while(rTable)
    {
        uint32_t curMask = rTable->mask.s_addr;
        uint32_t curDest = rTable->dest.s_addr;
        if(rMask == 0 || curMask > rMask)
        {
            /*Check with Longest Prefix Match Algorithm*/
            uint32_t newDestIP = (destIP & curMask);
            if(newDestIP == curDest)
            {
                rMask = curMask;
                rInterface = rTable->interface;
            } 
        }
        rTable = rTable->next;
    }
    return rInterface;
}


/***********************************************************
 * Method: sr_send_icmp
 *
 * Params: sr_instance* sr 
 *	   uint8*       oldpacket   
 *         uint         len
 *         uint8        type 
 *         uint8        code
 *         char*        interface
 *
 * Description:
 *  Creates an icmp packet of type $type with code $code,
 *  in response to $oldpacket through $interface and sends
 *  the packet using sr_send_packet(..).
 *
 **********************************************************/
void sr_send_icmp(struct sr_instance *sr, uint8_t *oldpacket, 
        unsigned int len, uint8_t type, uint8_t code, 
        char* interface){

    /* Sanity check on params */
    if(!sr || !oldpacket || !interface || !len){
        fprintf(stderr,"sr_send_icmp: bad parameters");
        return;
    }

    /* Create new buff */
    size_t buff_size = sizeof(sr_ethernet_hdr_t) +
        sizeof(sr_ip_hdr_t) +
        sizeof(sr_icmp_t3_hdr_t);

    /* if echo reply, sizes should match */
    if(type == 0) 
        buff_size = len;

    uint8_t *buff = (uint8_t*) malloc(buff_size);

    memset(buff,0,buff_size);

    /* init protocol data structures for buff and oldpacket */
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) buff;
    sr_ip_hdr_t *iphdr      = (sr_ip_hdr_t*) (buff + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmphdr  = (sr_icmp_t3_hdr_t*) (buff + sizeof(sr_ethernet_hdr_t) + 
            sizeof(sr_ip_hdr_t));

    sr_ethernet_hdr_t *old_ehdr = (sr_ethernet_hdr_t *) oldpacket;
    sr_ip_hdr_t *old_iphdr      = (sr_ip_hdr_t*) (oldpacket + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *old_icmphdr  = (sr_icmp_t3_hdr_t*) (oldpacket + sizeof(sr_ethernet_hdr_t) + 
            sizeof(sr_ip_hdr_t));

    struct sr_if *src_if = sr_get_interface(sr,interface); 

    /* fill in ICMP */
    if(type == 0){
        /* echo back the originial data from echo request */
        memcpy(buff,oldpacket,buff_size);
        /* Same ID and Seq fields are required in reply packet */
        icmphdr->unused    = old_icmphdr->unused;   /* ID Section */
        icmphdr->next_mtu  = old_icmphdr->next_mtu; /* Sequence Section */
    }
    else if(type == 3 || type== 11){
        /* Set data to old ip header + 8 bytes of its data */
        memcpy(icmphdr->data,old_iphdr,ICMP_DATA_SIZE);
    }
    else{
        fprintf(stderr,"sr_send_icmp: Unknown ICMP type %d",type);
        return;       
    }

    icmphdr->icmp_type = type;
    icmphdr->icmp_code = code;
    icmphdr->icmp_sum  = 0;


    /* fill in IP */
    iphdr->ip_tos = 0;
    iphdr->ip_hl  = 5;
    iphdr->ip_v   = 4;
    iphdr->ip_len = htons(buff_size - sizeof(sr_ethernet_hdr_t));
    iphdr->ip_id  = htons(old_iphdr->ip_id);
    iphdr->ip_off = htons(IP_DF); 
    iphdr->ip_ttl = 64;
    iphdr->ip_p   = ip_protocol_icmp;
    iphdr->ip_dst = old_iphdr->ip_src;
    iphdr->ip_src = src_if->ip;
    iphdr->ip_sum = 0;

    /* Calculate the checksums */
    icmphdr->icmp_sum  = cksum(icmphdr,ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));
    iphdr->ip_sum      = cksum((buff + sizeof(sr_ethernet_hdr_t)),(iphdr->ip_hl * 4));


    /* fill in ethernet */
    memcpy(ehdr->ether_dhost,old_ehdr->ether_shost,ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost,old_ehdr->ether_dhost,ETHER_ADDR_LEN);
    ehdr->ether_type = htons(ethertype_ip);

    /* DEBUG */
    /* print_hdrs(buff,buff_size); */

    /* Send it out */
    sr_send_packet(sr,buff,buff_size,interface);

    free(buff);
}



/*
 *   Translate the packet given a NAT mapping and Translate type  
 *
 **/
void sr_nat_translate(struct sr_instance* sr, uint8_t* packet, int len, struct sr_nat_mapping* mapping,
        sr_nat_trans_type trans_type){

    assert(sr);
    
    /* Thread_safety */
    pthread_mutex_lock(&(sr->nat.lock));
    
    assert(packet);
    assert(mapping);

    /* Sanity check on params */


    printf("*********************************Begin SR_NAT_TRANSLATE*********************************\n");

    /* init protocol data structures for packet */
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t *iphdr      = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmphdr  = (sr_icmp_t3_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + 
            sizeof(sr_ip_hdr_t));
    sr_tcp_hdr_t *tcphdr  = (sr_tcp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + 
            sizeof(sr_ip_hdr_t));

    struct sr_if *interface = NULL;

    /* Internal to External */
    if(trans_type == nat_trans_int_to_ext){

        /* Set new source IP */
        iphdr->ip_src = mapping->ip_ext;

        /* ICMP: Set new icmp ID and redo Checksum */
        if(mapping->type == nat_mapping_icmp){
            printf("ICMP Translation...\n");
            icmphdr->unused = mapping->aux_ext;
            icmphdr->icmp_sum  = 0; /* Clear first */
            icmphdr->icmp_sum  = cksum(icmphdr,ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));
        }
        /* TCP: Set new source port and redo Checksum */
        else if(mapping->type == nat_mapping_tcp){
            printf("TCP Translation...\n");

            uint32_t src_seq = tcphdr->ack_num-1;
            /* Update Connection State */
            struct sr_nat_connection* conn = 
            sr_nat_lookup_connection(&(sr->nat), mapping, mapping->ip_int, iphdr->ip_dst, src_seq, tcphdr->dest_port);
            if(conn){
                printf("Ext to Int: found a connection.\n");
                /* Determine the packet type (syn,ack,etc...) */
                /* Change the connection state accordingly */

                /*
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
                */
		
		if(conn->state == tcp_state_syn_sent)
                {
                        int ackBit = ((tcphdr->flag_state >> 4)&1)%2;
                        int syncBit = ((tcphdr->flag_state >> 1)&1)%2;
                        if(ackBit && syncBit)
                        {
                                conn->state = tcp_state_syn_recv;
                        }
                }
                else if(conn->state == tcp_state_syn_recv)
                {
			int ackBit = ((tcphdr->flag_state >> 4)&1)%2;
			if(ackBit)
			{
				conn->state = tcp_state_established;
			}	
                }
                else if(conn->state == tcp_state_established)
                {
                	int finBit = ((tcphdr->flag_state)&1)%2; 
			if(finBit)
			{
				conn->state = tcp_state_closed;
			}
      		}
                
                /*update the sequence number*/
                conn->src_seq = tcphdr->sequence_num;
                /* Update the timer */
                conn->last_updated = time(NULL);

            }else{
                printf("Ext to In: no connection found.\n");
                /*wait 6 seconds and if link exist then drop it. If not, then sent icmp unreachable.*/
            }
            tcphdr->src_port = mapping->aux_ext;
            tcphdr->checksum = 0; /* Clear first */
            tcphdr->checksum  = tcp_cksum(packet,len); 
            printf("The returned Checksum is: %i\n", tcphdr->checksum);
        }
        
        /* Change Ethernet Source and Destination ADDR */
        interface = sr_get_interface(sr, NAT_EXT);

    }
    /* External to Internal */
    else if(trans_type == nat_trans_ext_to_int){

        /* Set new destination IP */
        iphdr->ip_dst = mapping->ip_int;        

        /* ICMP: Set new icmp ID and redo Checksum */
        if(mapping->type == nat_mapping_icmp){
            printf("ICMP Translation...\n");
            icmphdr->unused = mapping->aux_int;
            icmphdr->icmp_sum  = 0; /* Clear first */
            icmphdr->icmp_sum  = cksum(icmphdr,ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));
        }
        /* TCP: Set new source port and redo Checksum */
        else if(mapping->type == nat_mapping_tcp){
            printf("TCP Translation...\n");
            uint32_t src_seq = tcphdr->ack_num-1;
            /* Update Connection State */
            struct sr_nat_connection* conn = 
              sr_nat_lookup_connection(&(sr->nat), mapping, mapping->ip_int,
                iphdr->ip_src, src_seq, tcphdr->src_port);
            if(conn){
                printf("Ext to Int: found a connection.\n");
                /* Determine the packet type (syn,ack,etc...) */
                /* Change the connection state accordingly */
		
           	if(conn->state == tcp_state_syn_sent)
                {
                        int ackBit = ((tcphdr->flag_state >> 4)&1)%2;
			int syncBit = ((tcphdr->flag_state >> 1)&1)%2;
                        if(ackBit && syncBit)
                        {
                                conn->state = tcp_state_syn_recv;
                        }
                }
		else if(conn->state == tcp_state_syn_recv)
                {
                        int ackBit = ((tcphdr->flag_state >> 4)&1)%2;
                        if(ackBit)
                        {
                                conn->state = tcp_state_established;
                        }
                }
                else if(conn->state == tcp_state_established)
                {
                        int finBit = ((tcphdr->flag_state)&1)%2; 
                        if(finBit)
                        {
                                conn->state = tcp_state_closed;
                        }
                }
 		
                /*update the sequence number*/
                conn->src_seq = tcphdr->sequence_num;
                /* Update the timer */
                conn->last_updated = time(NULL);
            }else{
                printf("Ext to In: no connection found.\n");
                /*wait 6 seconds and if link exist then drop it. If not, then sent icmp unreachable.*/
            }

            tcphdr->dest_port = mapping->aux_int;
            tcphdr->checksum = 0; /* Clear first */
            tcphdr->checksum  = tcp_cksum(packet,len); 
        }

        /* Change Ethernet Source and Destination ADDR */
        interface = sr_get_interface(sr, NAT_INT);

    }

    /* Change Ethernet Source and Destination ADDR */
    assert(interface);
    memcpy(ehdr->ether_dhost,interface->addr,ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost,interface->addr,ETHER_ADDR_LEN);

    /* Calculate IP checksum */
    iphdr->ip_sum = 0;
    iphdr->ip_sum = cksum((packet + sizeof(sr_ethernet_hdr_t)),(iphdr->ip_hl * 4));
    printf("IP checksum: %i\n", iphdr->ip_sum);
    printf("*********************************END SR_NAT_TRANSLATE*********************************\n");

    /* Update mappings' last_update */
    mapping->last_updated = time(NULL);
    
    /* release mutex */
    pthread_mutex_unlock(&(sr->nat.lock));

}

/*
* calculate and return the TCP checksum for a packet that has the
* format: Etherneti_hdr(IP_hdr(TCP_hdr(...)))
*
*/
uint16_t tcp_cksum(const void *packet, int len){

    assert(packet);

    printf("HEX: %x\n",cksum(packet,len));

    sr_tcp_pseudo_hdr_t *pseudo_hdr;
    unsigned char*  buf;
    unsigned int total_len = 0;
    uint16_t checksum   = 0;

    sr_ip_hdr_t *iphdr   = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + 
                                                      sizeof(sr_ip_hdr_t));
 
    /* Fill in pseudo header */
    pseudo_hdr = (sr_tcp_pseudo_hdr_t *)malloc(sizeof(sr_tcp_pseudo_hdr_t));	
    pseudo_hdr->ip_src = iphdr->ip_src;
    pseudo_hdr->ip_dst = iphdr->ip_dst;
    pseudo_hdr->reserved = 0;
    pseudo_hdr->protocol = (iphdr->ip_p);
    pseudo_hdr->len = htons(ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));
	
    uint16_t originalChecksum = tcphdr->checksum;
    printf("Original Checksum: %i\n", originalChecksum);
    tcphdr->checksum = 0;

    /* find the total len */
    total_len = ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_pseudo_hdr_t);
    
    buf = malloc(total_len);
    memcpy(buf, pseudo_hdr, sizeof(sr_tcp_pseudo_hdr_t));
    memcpy(buf+ sizeof(sr_tcp_pseudo_hdr_t), tcphdr, ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));

    /*print_hdrs(packet,len);*/
    printf("pseudo length: %lu\n",sizeof(sr_tcp_pseudo_hdr_t));
    printf("tcp total: %lu\n", ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));
    printf("tcp total+pseudo length: %d\n",total_len);
    
     
    checksum = cksum(buf,total_len);
    printf("checksum is : %i\n",checksum);
    tcphdr->checksum = originalChecksum;
    free(pseudo_hdr);
    free(buf);

    return checksum;
}
