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
#include "sr_utils.h"
/*
   Author: Tzu-Yao Chien 998758759
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

  printf("\n******************************PACKET START**********************************\n");
  print_hdrs(packet,len);
  printf("*** -> Received packet of length %d \n",len);
  /*Ethernet Sanity Check*/
  /* Check 1: length must at least the size of ethernet header*/
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) 
  {
    printf("Failed to pass ETHERNET header sanity check due to insufficient length\n");
    return;
  }
  if(len > 1514)
  {
    printf("Failed to pass ETHERNET header sanity check due to length over Ethernet MTU\n");
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
    printf("Failed to pass ETHERNET header sanity check due to bad interface name\n");
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
    printf("Failed to pass ETHERNET header sanity check due to bad destination header address\n");
    return;
  }
  
  /*check ethernet type*/
  uint16_t ethtype = ethertype(packet);
  /* IP packet*/
  if(ethtype == ethertype_ip)
  {
    printf("IP packet is found in the ethernet\n");
    /*Sanity Check ARP Packet*/
    /*Check 1: length*/
    minlength += sizeof(sr_ip_hdr_t);
    if (len < minlength) {
      printf("Failed to pass IP header sanity check due to insufficient length\n");
    }
    
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    /*Check 2: checksum*/
    int originalChecksum = iphdr->ip_sum;
    iphdr->ip_sum = 0;
    int calculatedChecksum = cksum((packet + sizeof(sr_ethernet_hdr_t)),ntohs(iphdr->ip_len));
    if(originalChecksum != calculatedChecksum)
    {
      printf("Failed to pass IP header sanity check due to calculated checksum: %d does not equal %d", calculatedChecksum, originalChecksum);
      return;
    }
    
    /*Check Dest IP*/
    uint32_t destIP = iphdr->ip_dst;
    uint32_t interfaceIP = srcInterface->ip;
    /*The packet is sending to router*/
    if(destIP == interfaceIP)
    {
      printf("A packet is sent to the router! If TCP then sent unreachable, if ICMP, then ECHO\n");
      /*TODO: Pouria's job*/
    }
    else
    {
      printf("Packet is sent to router to forward!\n");
      sr_print_routing_table(sr);
      /*Sanity Check*/
      /*Check 1: see if we have the destination address in router, if not then sent ICMP*/
      if(sr->routing_table == 0)
      {
	printf("IP Packet Forwarding Sanity Check Fail due to empty routing table\n");
        return;
      }
      struct sr_rt* rTable = sr->routing_table;
      char* rInterface = NULL;
      uint32_t rMask = 0;
      printf("DEBUG: Searching IP is: %d \n", destIP);
      while(rTable)
      {
	uint32_t curMask = rTable->mask.s_addr;
	uint32_t curDest = rTable->dest.s_addr;
	printf("DEBUG: curMask - %d, curDest -%d\n", curMask, curDest);
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
      if(rInterface == NULL)
      {
	printf("IP Forwarding Sanity Check fail due to no matching interface in routing table\n");
	return;
      }
      printf("The interface chosen is: %s \n", rInterface);
      /*check 2: see if TTL is valid, if not sent ICMP*/
      if(iphdr->ip_ttl < 2)
      {
	printf("IP Forwarding Sanity Check fails due to less than 2 TTL\n");
	/*TODO: Sent ICMP Packet*/
      }
      /*Find MAC address by look up requested destination IP in cache*/
      struct sr_arpentry* cacheEntry = sr_arpcache_lookup(&sr->cache, destIP);
      if(cacheEntry != NULL)
      {
        printf("Look up is not null, repackage the packet and forward it\n");
        /* this might crush free(lookupResult);*/
	/*Now pack everything with new checksum and TTL and send */
	struct sr_if* curInterface = sr_get_interface(sr, rInterface);
	iphdr->ip_ttl -= 1;
	/*Calculate new checksum*/
    	iphdr->ip_sum = 0;
    	iphdr->ip_sum = cksum((packet + sizeof(sr_ethernet_hdr_t)),ntohs(iphdr->ip_len));
	memcpy(ehdr->ether_shost, curInterface->addr, ETHER_ADDR_LEN);
	memcpy(ehdr->ether_dhost, cacheEntry->mac, ETHER_ADDR_LEN);
	/*dump it out and see*/
        printf("Header Build By Us:\n");
	print_hdrs(packet,len);
        sr_send_packet(sr, packet, len, rInterface);
	free(cacheEntry);
      }
      else
      {
	printf("No result in the cache table, make ARP request!\n");
	struct sr_arpreq* currentRequest = sr_arpcache_queuereq(&sr->cache, destIP, packet, len, interface);
	printf("The inserted ip: %d, and destIP: %d \n", currentRequest->ip, destIP);
	/*TODO Need to free sr_arpreq*/
      }
    }
  }
  /*ARP*/
  else if(ethtype == ethertype_arp)
  {
     printf("ARP packet is found in the ethernet\n");
     /*Sanity check ARP packet*/
     minlength += sizeof(sr_arp_hdr_t);
     if (len < minlength)
     {
       printf("Failed to pass ARP header sanity check due to insufficient length\n");
       return;
     }
     sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
     if(ntohs(arp_hdr->ar_op) == arp_op_request)
     {
	printf("Program receive an ARP REQUEST\n");
	/*Save the src destination to cache*/
	unsigned char *srcMacAddr = arp_hdr->ar_sha;
	uint32_t srcIP = arp_hdr->ar_sip;
	sr_arpcache_insert(&sr->cache, srcMacAddr, srcIP);
	uint32_t destIP = arp_hdr->ar_tip;
	/*Check interface's IP with target IP*/
	uint32_t interfaceIP = srcInterface->ip;
	if(interfaceIP == destIP)
	{
	  printf("The Interface IP and ARP target IP matches!\n");
	  arp_hdr->ar_op  = htons(arp_op_reply);
	  memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
	  arp_hdr->ar_tip = arp_hdr->ar_sip;
	  memcpy(arp_hdr->ar_sha, srcInterface->addr, ETHER_ADDR_LEN);
	  arp_hdr->ar_sip = interfaceIP;
	  memcpy(ehdr->ether_shost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
	  memcpy(ehdr->ether_dhost, arp_hdr->ar_tha, ETHER_ADDR_LEN);
	  /*dump it out and see*/
	  printf("Header Build By Us:\n");
	  print_hdrs(packet,len);
	  sr_send_packet(sr, packet, len, interface);
	}
     }
     else if(ntohs(arp_hdr->ar_op) == arp_op_reply)
     {
	printf("ARP receive a reply\n");
	/*Add the reply to cache table*/
	unsigned char *srcMacAddr = arp_hdr->ar_sha;
        uint32_t srcIP = arp_hdr->ar_sip;
        sr_arpcache_insert(&sr->cache, srcMacAddr, srcIP);
	sr_arpcache_dump(&sr->cache);
		
	/*Find the request in the sweep queue, and continue all waiting packet by calling handle packet*/
    	struct sr_arpreq* request = sr->cache.requests;
	/*printf("The request IP is: %d\n", request->ip);*/
    	while(request)
    	{
	  printf("Request queue is not empty\n");
	  if(request->ip == srcIP)
	  {
	    struct sr_packet* package = request->packets;
	    while(package)
	    {
	      printf("Found a package that's waiting for the reply\n");
	      sr_handlepacket(sr, package->buf, package->len, package->iface);
	      package = package->next;
	    }
	    sr_arpreq_destroy(&sr->cache, request);
	  }
	  else
	  {
	    request = request->next;
	  }
	}
	
     }
     else
     {
       printf("Failed due to bad arp option code: %d\n", ntohs(arp_hdr->ar_op));
       return;
     }
  }  
  /*Unknown*/
  else
  {
    printf("Unrecognized Ethernet Type: %d\n", ethtype);
  }
  
  printf("\n******************************PACKET END**********************************\n");


  /* Psuedocode 
 * 
 *   Check Ethernet min length
 *   If ethType = IP then:
 *      Check IP min len
 *      Verify IP Checksum
 *      If destAddr matches one of router's interfaces then:
 *          If ICMP echo request
 *              verify ICMP checksum
 *              send back ICMP echo reply
 *          elseif it has TCP/UDP payload
 *              send back ICMP port unreachable
 *          else
 *              ignore
 *      else
 *          If TTL =< 0:
 *              ICMP error
 *          Decrement TTL by 1
 *          Recalculate checksum and repack IP
 *          Lookup destAddr in routing table to find next-hop IP
 *          If not found:
 *              send back ICMP error net unreachable
 *          Lookup next-hop IP in ArpCache table
 *          if a match is found:
 *              pack everything in an ethernet frame and send to corresponding interface
 *          else:
 *              send out an ARP request for the next-hop IP, through every interface
 *              (or just simply add a request in the queue for ArpCache_sweepreq() )
 *   
 *   elseif ethType = ARP:
 *      Check ARP min len
 *      if opcode = request:
 *          if destination matches any of router's interfaces:
 *              send back an ARP reply with all fields filled in
 *           else
 *              ignore;
 *      elseif opcode = reply:
 *          find which ARP request it is replying to and remove it from the queue
 *          add the newly retrieved MAC/IP to ARPCache table
 *          pack and send the original packet that was waiting for this MAC address
 *      else
 *          error: bad-opcode (or just ignore)
 *   else
 *      error: unknown ethernet type
 *
 *
 *              
 */


}/* end sr_ForwardPacket */

