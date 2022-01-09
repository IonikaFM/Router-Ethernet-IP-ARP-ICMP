#include <queue.h>
#include "skel.h"

queue q = NULL;

struct route_table {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
};

struct route_table *table_route;
int route_lines = 0;

int router_parser(char *file_name){
	FILE *file = fopen(file_name, "r");
	if(file == NULL){
		fprintf(stderr, "File rtable.txt can not be opened !");
	}

	char read[100];
	int count = 0;
	while(fgets(read, sizeof(read), file)) {
		char *p = strtok(read, " ");
		table_route[count].prefix = ntohl(inet_addr(p));
		p = strtok(NULL, " ");
		table_route[count].next_hop = ntohl(inet_addr(p));
		p = strtok(NULL, " ");
		table_route[count].mask = ntohl(inet_addr(p));
		p = strtok(NULL, " ");
		table_route[count].interface = atoi(p);
		count ++;
	}
	fclose(file);
	return count;
}

struct route_table *get_best_route(__u32 dest_ip) {
	
	uint32_t max = 0;
	struct route_table *best_route = NULL;
	for(int i = 0 ; i < route_lines; i ++){
		if((table_route[i].mask & dest_ip) == table_route[i].prefix){
			if(max < table_route[i].prefix || max == 0){
				max = table_route[i].prefix;
				best_route = &table_route[i];
			}
		}
	}
	return best_route;
}

typedef struct arp_table {
	uint32_t ip;
	uint8_t mac[6];
};

struct arp_table *table_arp;
int arp_lines = 0;

struct arp_table *get_arp(__u32 ip) {

	for(int i = 0; i < arp_lines; i ++){
		if(table_arp[i].ip == ip)
			return &table_arp[i];
	}

    return NULL;
}

void handle_arp(packet m){
	struct ether_header *eth_header = (struct ether_header *)m.payload;
	struct arp_header* my_arp = parse_arp(m.payload);

	if(my_arp->op == htons(ARPOP_REQUEST)){
		struct in_addr address;
		inet_aton(get_interface_ip(m.interface), &address);

		if(my_arp->tpa == address.s_addr) {
			
			struct ether_header *newHeader = (struct ether_header *)malloc(sizeof (struct ether_header));
			memcpy(newHeader->ether_dhost, my_arp->sha, 6);
			get_interface_mac(m.interface, newHeader->ether_shost);
			newHeader->ether_type = eth_header->ether_type;

			send_arp(my_arp->spa, my_arp->tpa, newHeader, m.interface, htons(ARPOP_REPLY));
		}
	} else if (my_arp->op == htons(ARPOP_REPLY)) {
		arp_lines ++;
		table_arp[arp_lines].ip = my_arp->spa;
		memcpy(table_arp[arp_lines].mac, my_arp->sha, 6);
		if(!queue_empty(q)) {
			packet *new_packet = (packet *)malloc(sizeof(packet));
			memcpy(new_packet, queue_deq(q), sizeof(packet));

			struct ether_header *eth = (struct ether_header *)new_packet->payload;
			struct iphdr *ip = (struct iphdr *)(new_packet->payload + sizeof(struct ether_header));

			struct route_table *best_route = get_best_route(ntohl(ip->daddr));

			memcpy(eth->ether_dhost, table_arp[arp_lines].mac, 6);
			get_interface_mac(new_packet->interface, eth->ether_shost);
			send_packet(best_route->interface, new_packet);
		}
	}
}

void handle_ip(packet m){
	struct ether_header *eth_header = (struct ether_header *)m.payload;
	struct iphdr *ip_header = (struct iphdr *)(m.payload + sizeof(struct ether_header));

	struct icmphdr *icmp_header = parse_icmp(m.payload);
	struct in_addr interface_ip ;
	inet_aton(get_interface_ip(m.interface), & interface_ip);
	u_int8_t interface_mac[6];
	get_interface_mac(m.interface, interface_mac);
	
	if(ip_header->daddr == interface_ip.s_addr && icmp_header->type == 8 && icmp_header != NULL) {
		send_icmp(interface_ip.s_addr, ip_header->saddr, interface_mac, eth_header->ether_dhost, 0, 0, m.interface,icmp_header->un.echo.id, icmp_header->un.echo.sequence);
		return ;
	}

	if(ip_checksum(ip_header, sizeof(struct iphdr)) != 0){
		fprintf(stderr, "Wrong checksum !\n");
		return ;
	}

	if(ip_header->ttl <= 1){
		send_icmp_error(interface_ip.s_addr, ip_header->saddr, interface_mac, eth_header->ether_dhost,11, 0, m.interface);
		return ;
	}

	ip_header->ttl --;

	ip_header->check = 0;
	ip_header->check = ip_checksum(ip_header, sizeof(struct iphdr));

	struct route_table *best_route = get_best_route(ntohl(ip_header->daddr));
	if(best_route == NULL) {
		send_icmp_error(interface_ip.s_addr, ip_header->saddr, interface_mac, eth_header->ether_dhost, 3, 0, m.interface);
		return ;
	}

	struct arp_table *arp_entry = get_arp(htonl(best_route->next_hop));
	if(arp_entry == NULL) {
		struct ether_header *newHeader = (struct ether_header *)malloc(sizeof (struct ether_header));

		memset(newHeader->ether_dhost, 0xFF, sizeof(newHeader->ether_dhost));
		get_interface_mac(best_route->interface, newHeader->ether_shost);
		newHeader->ether_type = htons(ETHERTYPE_ARP);

		struct in_addr interface_ip;
		inet_aton(get_interface_ip(best_route->interface), &interface_ip);

		send_arp(htonl(best_route->next_hop), interface_ip.s_addr, newHeader, best_route->interface, htons(ARPOP_REQUEST));

		packet *new_packet = (packet *)malloc(sizeof(packet));
		memcpy(new_packet, &m, sizeof(packet));
		queue_enq(q, new_packet);
	} else {
		memcpy(eth_header->ether_dhost, arp_entry->mac, 6);
		send_packet(best_route->interface, &m);
	}
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);
	
	q = queue_create();

	table_route = (struct route_table *)malloc(sizeof(struct route_table) * 65000);
	route_lines = router_parser(argv[1]);

	table_arp = (struct arp_table *)malloc(sizeof(struct arp_table) * 65000);
	
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_header = (struct ether_header *)m.payload;

		if(eth_header->ether_type == htons(ETHERTYPE_ARP)) {
			handle_arp(m);
		} else if(eth_header->ether_type == htons(ETHERTYPE_IP)) {
			handle_ip(m);
		}
	}
}
