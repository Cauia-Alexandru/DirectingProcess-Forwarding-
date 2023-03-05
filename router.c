#include "queue.h"
#include "skel.h"
#include <stdbool.h>
struct route_table_entry *route_table;
int route_table_length;
struct arp_entry *arp_en;
int arp_en_length;
int interfaces[ROUTER_NUM_INTERFACES];

//returneaza un pointer de tip arp_entry catre o intrare din tabela arp care corespunde
//adresei ip cautate.Returneaza null daca nu gaseste
struct arp_entry *get_arp_entry(uint32_t destination_ip)
{
	for (int i = 0; i < arp_en_length; i++)
	{
		if (destination_ip == arp_en[i].ip)
			return &arp_en[i];
	}
	return NULL;
}


//functia returneaza headerul icmp-ului din payload
struct icmphdr* icmp_header(void *buffer)
{
	struct ether_header *eth_hdr;
	struct iphdr *ip_header;

	eth_hdr = (struct ether_header*)buffer;
	if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
		ip_header = (struct iphdr*)(buffer + sizeof(struct ether_header));
		if(ip_header->protocol == 1){
			struct icmphdr *icmp_hdr;
			icmp_hdr = (struct icmphdr *)(buffer + sizeof(struct iphdr) + sizeof(struct ether_header));
			return icmp_hdr;
		}
		else
			return NULL;
	}
	else
		return NULL;
}

void build_eth_hdr(struct ether_header *eth_hdr, uint8_t *sha, uint8_t *dha, unsigned short type)
{
	memcpy(eth_hdr->ether_dhost, dha, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, sha, ETH_ALEN);
	eth_hdr->ether_type = type;
}

//functia formeaza un pachet icmp si il trimite destinatiei
//am o variabila "error" care o folosesc pentru a verifica daca pachetul are eroare
//ca sa completez campurile seq si id
void send_icmp(uint32_t dest_addr, uint32_t source_addr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface, int id, int seq, bool error)
{
	struct ether_header eth_hdr;
	struct iphdr ip_header;
	struct icmphdr icmp_header;
	//completez campurile structurii icmphdr
	icmp_header.type = type;
	icmp_header.code = code;
	icmp_header.checksum = 0;
	if(error == true){
		icmp_header.un.echo.id = id;
		icmp_header.un.echo.sequence = seq;
	}

	packet packet;
	void* payload;

	build_eth_hdr(&eth_hdr, sha, dha, htons(ETHERTYPE_IP));
	//completez campurile structurii iphdr
	ip_header.check = 0;
	ip_header.daddr = dest_addr;
	ip_header.frag_off = 0;
	ip_header.id = htons(1);
	ip_header.ihl = 5;
	ip_header.protocol = 1;
	ip_header.saddr = source_addr;
	ip_header.tos = 0;
	ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_header.ttl = 64;
	ip_header.version = 4;
	ip_header.check = ip_checksum((uint8_t*)&ip_header, sizeof(struct iphdr));

	icmp_header.checksum = icmp_checksum((uint16_t*)&icmp_header, sizeof(struct icmphdr));
	payload = packet.payload;
	//introduc in payload toate informatiile
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &ip_header, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_header, sizeof(struct icmphdr));
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	packet.interface = interface;
	//trimit pachetul
	send_packet(&packet);

}

//am utilizat cautarea binara pentru a gasi cea mai buna ruta
//cautarea este aplicata deja pe tabela sortata cu qsort
//complexitatea O(logn)
struct route_table_entry *LPM(uint32_t ip_destination, struct route_table_entry* r_table, int table_len){
	int start = 0;
	int end = table_len - 1;
	int middle = (start + end) / 2;
	struct route_table_entry* res = NULL;
	while(start <= end){
		middle = (start + end) / 2;

		if((ip_destination & r_table[middle].mask) == r_table[middle].prefix)
			res = &r_table[middle];

		if(r_table[middle].prefix > (ip_destination & r_table[middle].mask))
			start = middle + 1;

		else
			end = middle - 1;
	}
	return res;
}

//functia de comparare care o folosesc la qsort
//ordon descrecator dupa prefix, daca sunt egale, dupa masca 
int compare_prefix(const void *x, const void *y){
	int cmp = ((struct route_table_entry*)y)->prefix -
	((struct route_table_entry*)x)->prefix;
	if(cmp == 0){
		return ((struct route_table_entry*)y)->mask -
	((struct route_table_entry*)x)->mask;
	}
	return cmp;
}

//functie care calculeaza checksum-ul dupa decrementarea ttl-ului
//returneaza noul checksum si actualizeaza ttl
uint16_t bonus(struct iphdr* ipheader){
	uint16_t old_ttl = ipheader->ttl;
	ipheader->ttl--;
	uint16_t new_ttl = ipheader->ttl;
	return ipheader->check - ~old_ttl - new_ttl - 1;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	//aloc memorie pentru tabele
	route_table = malloc(sizeof(struct route_table_entry) * 70000);
	arp_en = malloc(sizeof(struct arp_entry) * 10);
	route_table_length = read_rtable(argv[1], route_table);
	//sortez descrescator route_teble
	qsort(route_table, route_table_length, sizeof(struct route_table_entry), compare_prefix);

	arp_en_length = parse_arp_table("arp_table.txt", arp_en);

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1)
	{
		//routerul primeste un pachet
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		//
		struct iphdr *iph;
		struct ether_header *eth_header = (struct ether_header *)m.payload;
		//verific daca protocolul Ethernetului este de tip ip
		if(ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
			continue;
		} else {
			iph = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		}
		struct icmphdr* icmp_hdr = icmp_header(m.payload);
		if(icmp_hdr){
			//daca mesajul este de tip echo request
			if(icmp_hdr->type == ICMP_ECHO){
				//daca adresa destinatie este aceiasi cu cea a routerului
				if(iph->daddr == inet_addr(get_interface_ip(m.interface))){
					//atunci trimit un packet icmp cu raspuns echo reply
					send_icmp(iph->saddr, iph->daddr, eth_header->ether_dhost,
					eth_header->ether_shost, ICMP_ECHOREPLY, 0, m.interface,
					icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence, true);
					continue;
				}
			}
		}

		//calculez checksum-ul, daca e gresit arunc pachetul
		int check = iph->check;
		iph->check = 0;
		if(ip_checksum((uint8_t*)iph, sizeof(struct iphdr)) != check)
			continue;
		
		iph->check = check;
		//daca ttl e 0 sau 1 
		if (iph->ttl <= 1){
			//trimit un packet icmp cu mesajul de eroare "time exceeded"
			send_icmp(iph->saddr, iph->daddr, eth_header->ether_dhost,
					eth_header->ether_shost, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, m.interface,
					0, 0, false);
			continue;
		}

		//caut cea mai buna ruta din tabelul de rutare
		struct route_table_entry *the_best_route = LPM(iph->daddr, route_table, route_table_length);
		if (the_best_route == NULL){
			//daca nu sa gasiot trimit un mesaj de eroare icmp "destinatioon unreachable"
			send_icmp(iph->saddr, iph->daddr, eth_header->ether_dhost,
					eth_header->ether_shost, ICMP_UNREACH, ICMP_UNREACH_NET, m.interface,
					0, 0, false);
			continue;
		}

		struct arp_entry *arp = get_arp_entry(the_best_route->next_hop);
		if (arp == NULL)
			continue;

		iph->check = bonus(iph);
		
		get_interface_mac(the_best_route->interface, eth_header->ether_shost);
		memcpy(eth_header->ether_dhost, arp->mac, ETH_ALEN);
		m.interface = the_best_route->interface;
		send_packet(&m);
		
	}
}
