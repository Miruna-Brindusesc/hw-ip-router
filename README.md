
# Homework: IP Router in C

This project implements a simple IP router in **C**, capable of routing IPv4 packets and handling **ARP** and **ICMP** messages. The router uses a **binary trie** to perform efficient **Longest Prefix Match** lookups when forwarding IP packets. Pending packets are buffered while awaiting ARP resolution, ensuring no packet loss.

The repository is modular, separating router logic, protocol definitions, and helper data structures.

## Project Structure

```
.
├── Makefile            # Build rules for compiling and running the router
├── README              # Project documentation
├── arp_table1.txt      # Static ARP table used for testing
│
├── include/            # Header files
│   ├── lib.h           # Utility function declarations
│   ├── list.h          # Linked list interface
│   ├── protocols.h     # Ethernet, IP, ARP, ICMP headers
│   └── queue.h         # Queue interface for packet buffering
│
├── lib/                # Helper library implementations
│   ├── 2025            # Infrastructure files from the assignment
│   ├── lib.c           # Utility functions implementation
│   ├── list.c          # Linked list implementation
│   └── queue.c         # Queue implementation
│
├── router.c            # Main router logic (packet forwarding, ARP, ICMP, routing)
├── rtable0.txt         # Routing table example for testing
└── rtable1.txt         # Alternative routing table configuration
```



## Main Features

### IP Routing

* Implements **Longest Prefix Match** using a **binary trie**.
* Function `get_best_route()` searches for the optimal route for a given IPv4 address.
* Validates **IP checksum** and **TTL**.
* Forwards packets to the next hop or sends **ICMP errors** if:

  * No route exists (Type 3 → Destination Unreachable)
  * TTL ≤ 0 (Type 11 → TTL Exceeded)

### ARP Protocol

Main functions: `send_arp_request()`, `get_arp_entry()`.

* Generates an **ARP request** if the MAC address of the next hop is unknown.
* Stores pending packets in `packets_queue` while waiting for ARP resolution.
* Updates the **ARP table** upon receiving a reply and retransmits queued packets.
* Sends an **ARP reply** if the router is the target of an ARP request.

### ICMP Protocol

Main function: `send_icmp()`

* Responds to **ICMP Echo Requests (ping)**.
* Sends ICMP error messages:

  * Type 0 → Echo Reply
  * Type 11 → TTL Exceeded
  * Type 3 → Destination Unreachable

### Helper Functions

* `swap()` – Swaps two memory regions.
* `is_broadcast()` – Checks if a MAC address is a broadcast address.
* `is_equal_mac()` – Compares two MAC addresses.
* `set_ethernet_header_1()` / `set_ethernet_header_2()` – Builds Ethernet headers for ARP/IP.
* `set_ip_header()` – Constructs IP headers for ICMP messages.

## Key Data Structures

### Routing Trie

Used for **Longest Prefix Match** lookups.

```c
struct trie {
    struct route_table_entry *route; // Routing entry at this node
    struct trie *left;               // Bit 0 branch
    struct trie *right;              // Bit 1 branch
};
```

### Important Global Variables

```c
struct trie *root;                  // Root of the routing trie
struct route_table_entry *rtable;   // Routing table
int rtable_len;                     // Number of entries in routing table

struct arp_entry *arp_table;        // ARP cache
int arp_table_len;                  // Number of ARP entries

struct packet_queue *packets_queue; // Pending packets awaiting ARP replies
```

## Build & Run

### Requirements

* **GCC** compiler
* **Make**
* Linux / WSL / macOS environment

### Compile

```bash
make
```

### Run Examples

```bash
# Run router with rtable0.txt and interfaces r-0, r-1
make run_router0

# Run router with rtable1.txt and interfaces r-0, r-1
make run_router1
```

### Makefile Targets

* `make clean` — remove compiled binaries
* `make run_router0` / `make run_router1` — run router with test routing tables

## Assignment Requirements & Implementation

| Requirement              | Description                                     | Implementation                                                                        |
|  | -- | - |
| **Routing Process**      | Validate IP, TTL, checksum, and forward packets | TTL checked and decremented, checksum recomputed, packet forwarded or ICMP error sent |
| **Longest Prefix Match** | Efficient route lookup                          | Implemented using a **binary trie** (`get_best_route()`)                              |
| **ARP Protocol**         | Request MAC if unknown, maintain ARP cache      | Dynamic ARP table, `packets_queue`, broadcast requests, reply handling                |
| **ICMP Protocol**        | Echo reply and error messages                   | Type 0 (Echo Reply), Type 11 (TTL exceeded), Type 3 (Destination unreachable)         |


## Testing & Verification

* Test routing and ARP functionality using `rtable0.txt` or `rtable1.txt`.
* Use `ping` or packet capture tools (e.g., Wireshark) to verify ICMP responses.
* Confirm that pending packets are correctly queued while awaiting ARP resolution.


