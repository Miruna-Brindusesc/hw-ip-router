#include "queue.h"
#include "lib.h"
#include "protocols.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#define MAX 100000

// Trie Structure
// Used to implement Longest Prefix Match for routing
typedef struct trie {
	struct route_table_entry *route;
	struct trie *left, *right;
} trie_t;

// Global Variables
static struct route_table_entry *rtable;   // Routing table
static int rtable_len;

static struct arp_table_entry *arp_table;  // ARP table
static int arp_table_len;

static trie_t *root;        // Root node of the trie
static queue packets_queue; // Queue for packets waiting for ARP resolution

// Helper Functions

// Swap two memory regions
void swap(void *a, void *b, size_t size) {
	uint8_t aux_1[256];

	// Use heap memory if region is larger than local buffer
	if (size > sizeof(aux_1)) {
		void *aux_2 = malloc(size);
		DIE(aux_2 == NULL, "Failed swap");

		memcpy(aux_2, a, size);
		memcpy(a, b, size);
		memcpy(b, aux_2, size);

		free(aux_2);
		return;
	}

	// For small regions avoid malloc
	memcpy(aux_1, a, size);
	memcpy(a, b, size);
	memcpy(b, aux_1, size);
}

// Check if a MAC address is broadcast
int is_broadcast(uint8_t addr[6]) {
	static const uint8_t broadcast_mac[6] = {255,255,255,255,255,255};
	return memcmp(addr, broadcast_mac, 6) == 0;
}

// Compare two MAC addresses
int is_equal_mac(uint8_t a[6], uint8_t b[6]) {
	return memcmp(a, b, 6) == 0;
}

// Set Ethernet header fields for ARP reply
void set_ethernet_header_1(struct ether_hdr *eth, struct arp_hdr *arp) {
	memcpy(eth->ethr_shost, arp->shwa, 6);
	memcpy(eth->ethr_dhost, arp->thwa, 6);
}

// Set Ethernet header fields when forwarding packets
void set_ethernet_header_2(struct ether_hdr *eth, struct arp_hdr *arp) {
	memcpy(eth->ethr_shost, arp->thwa, 6);
	memcpy(eth->ethr_dhost, arp->shwa, 6);
}

// Build an IP header for ICMP packets
void set_ip_header(struct ip_hdr *ip, uint32_t dest_addr, int interface) {
	ip->ver = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(92);
	ip->id = htons(1);
	ip->frag = 0;
	ip->ttl = 64;
	ip->proto = 1; // ICMP
	ip->source_addr = inet_addr(get_interface_ip(interface));
	ip->dest_addr = dest_addr;

	ip->checksum = 0;
	ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));
}

// Trie Functions

// Add a routing entry into the trie
int add_trie_node(struct route_table_entry *route) {

	uint32_t mask = 0;
	uint32_t prefix = ntohl(route->prefix);
	uint32_t netmask = ntohl(route->mask);

	// Allocate root if needed
	if (root == NULL) {
		root = calloc(1, sizeof(trie_t));
		if (root == NULL) {
			fprintf(stderr, "Failed to allocate trie root\n");
			return -1;
		}
	}

	trie_t *node = root;

	// Traverse bits of prefix
	for (int i = 31; i >= 0; i--) {

		// Stop when full mask length is reached
		if (mask == netmask) {
			node->route = route;
			return 0;
		}

		uint8_t bit = (prefix >> i) & 1;

		// Go left for bit 0
		if (bit == 0) {

			if (node->left == NULL) {
				node->left = calloc(1, sizeof(trie_t));
				if (node->left == NULL) return -1;
			}

			node = node->left;
		}

		// Go right for bit 1
		else {

			if (node->right == NULL) {
				node->right = calloc(1, sizeof(trie_t));
				if (node->right == NULL) return -1;
			}

			node = node->right;
		}

		mask |= (1 << i);
	}

	return 0;
}

// Build the trie from the routing table
int set_trie_table() {

	for (int i = 0; i < rtable_len; i++) {

		if (add_trie_node(&rtable[i]) != 0) {
			fprintf(stderr, "Failed to insert route in trie\n");
			return -1;
		}
	}

	return 0;
}

// Find best route using Longest Prefix Match
struct route_table_entry *get_best_route(uint32_t ip_dest) {

	struct route_table_entry *best_route = NULL;
	trie_t *node = root;

	uint32_t ip = ntohl(ip_dest);

	// Traverse trie using IP bits
	for (int i = 31; i >= 0 && node != NULL; i--) {

		if (node->route != NULL)
			best_route = node->route;

		uint8_t bit = (ip >> i) & 1;

		if (bit == 0)
			node = node->left;
		else
			node = node->right;
	}

	return best_route;
}

// ARP Functions

// Search ARP table for IP address
struct arp_table_entry *get_arp_entry(uint32_t ip) {

	for (int i = 0; i < arp_table_len; i++)
		if (arp_table[i].ip == ip)
			return &arp_table[i];

	return NULL;
}

// Send ARP request for next hop
void send_arp_request(void *buf, struct route_table_entry *entry) {

	char req[MAX_PACKET_LEN];

	struct ether_hdr *eth_hdr = malloc(sizeof(struct ether_hdr));
	DIE(eth_hdr == NULL, "Failed ether_hdr");

	eth_hdr->ethr_type = htons(0x0806); // ARP
	get_interface_mac(entry->interface, eth_hdr->ethr_shost);
	memset(eth_hdr->ethr_dhost, 0xFF, 6); // Broadcast

	struct arp_hdr *arp_hdr = malloc(sizeof(struct arp_hdr));
	DIE(arp_hdr == NULL, "Failed arp_hdr");

	arp_hdr->hw_type = htons(1);
	arp_hdr->proto_type = htons(0x0800);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(1); // Request

	get_interface_mac(entry->interface, arp_hdr->shwa);
	arp_hdr->sprotoa = inet_addr(get_interface_ip(entry->interface));
	arp_hdr->tprotoa = entry->next_hop;

	memcpy(req, eth_hdr, sizeof(struct ether_hdr));
	memcpy(req + sizeof(struct ether_hdr), arp_hdr, sizeof(struct arp_hdr));

	// Save original packet while waiting for ARP reply
	struct ip_hdr *saved_packet = malloc(98);
	memcpy(saved_packet, buf, 98);

	queue_enq(packets_queue, saved_packet);

	send_to_link(42, req, entry->interface);

	free(eth_hdr);
	free(arp_hdr);
}

// ICMP Function

// Send ICMP message (echo reply or error)
void send_icmp(int interface, char *buf, uint8_t type, int is_error) {

	char packet[MAX_PACKET_LEN];

	struct ether_hdr *eth;
	struct ip_hdr *ip;
	struct icmp_hdr *icmp;

	// ICMP error packet
	if (is_error) {

		eth = (struct ether_hdr *)packet;
		ip = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
		icmp = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

		memcpy(eth, buf, sizeof(struct ether_hdr));
		swap(eth->ethr_shost, eth->ethr_dhost, 6);

		const struct ip_hdr *old_ip = (const struct ip_hdr *)(buf + sizeof(struct ether_hdr));

		set_ip_header(ip, old_ip->source_addr, interface);

		icmp->mtype = type;
		icmp->mcode = 0;

		icmp->check = 0;
		icmp->check = htons(checksum((uint16_t *)icmp, 64 + sizeof(struct icmp_hdr)));

		send_to_link(98, packet, interface);
	}

	// ICMP Echo Reply
	else {

		eth = (struct ether_hdr *)buf;
		ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
		icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

		swap(eth->ethr_shost, eth->ethr_dhost, 6);
		swap(&ip->source_addr, &ip->dest_addr, sizeof(uint32_t));

		ip->ttl--;

		ip->checksum = 0;
		ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

		icmp->mtype = type;
		icmp->mcode = 0;

		icmp->check = 0;
		icmp->check = htons(checksum((uint16_t *)icmp, ntohs(ip->tot_len) - sizeof(struct ip_hdr)));

		send_to_link(98, buf, interface);
	}
}

// Main

int main(int argc, char *argv[]) {

	char buf[MAX_PACKET_LEN];

	// Initialize router interfaces
	init(argv + 2, argc - 2);

	// Allocate routing and ARP tables
	rtable = malloc(MAX * sizeof(struct route_table_entry));
	arp_table = malloc(MAX * sizeof(struct arp_table_entry));

	DIE(rtable == NULL || arp_table == NULL, "Memory allocation failed");

	rtable_len = read_rtable(argv[1], rtable);

	// Create queue for pending packets
	packets_queue = create_queue();

	// Build routing trie
	DIE(set_trie_table() < 0, "Trie creation failed");

	// Main packet processing loop
	while (1) {

		size_t len;

		// Receive packet
		int interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "Receive failed");

		struct ether_hdr *eth = (struct ether_hdr *)buf;

		uint16_t ether_type = ntohs(eth->ethr_type);

		// - IP PACKETS -
		if (ether_type == 0x0800) {

			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

			// Verify checksum
			uint16_t old_checksum = ip_hdr->checksum;
			ip_hdr->checksum = 0;

			if (htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr))) != old_checksum)
				continue;

			// Check TTL
			if (ip_hdr->ttl <= 1) {
				send_icmp(interface, buf, 11, 1);
				continue;
			}

			// Decrement TTL
			ip_hdr->ttl--;

			ip_hdr->checksum = 0;
			ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

			// Find best route
			struct route_table_entry *route = get_best_route(ip_hdr->dest_addr);

			if (!route) {
				send_icmp(interface, buf, 3, 1);
				continue;
			}

			// Get ARP entry
			struct arp_table_entry *arp_entry = get_arp_entry(route->next_hop);

			if (!arp_entry) {
				send_arp_request(buf, route);
				continue;
			}

			memcpy(eth->ethr_dhost, arp_entry->mac, 6);

			send_to_link(len, buf, route->interface);
		}

		// - ARP PACKETS -
		else if (ether_type == 0x0806) {

			struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

			// ARP request
			if (ntohs(arp->opcode) == 1) {

				arp->opcode = htons(2);

				swap(&arp->sprotoa, &arp->tprotoa, sizeof(uint32_t));

				send_to_link(42, buf, interface);
			}

			// ARP reply
			if (ntohs(arp->opcode) == 2) {

				struct arp_table_entry arp_entry;

				arp_entry.ip = arp->sprotoa;
				memcpy(arp_entry.mac, arp->shwa, 6);

				arp_table[arp_table_len++] = arp_entry;
			}
		}
	}

	return 0;
}