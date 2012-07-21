#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>

#define NF_ARP_PRI_FIRST INT_MIN

static struct nf_hook_ops nfho_out;      //struct holding set of hook function options
static struct nf_hook_ops nfarp_out;      //struct holding set of hook function options

static struct sk_buff *sock_buff;
static struct udphdr *udp_header;
static struct iphdr *ip_header;
static struct ethhdr *eth_header;

typedef struct ADDRINFO{
	u_char macaddr[ETH_ALEN];
} __attribute__((packed)) ADDRINFO;

static struct ADDRINFO* addrinfos[256];

typedef struct arpmsg{
	struct ethhdr eth;
	u_short htype;
	u_short ptype;
	u_char hlen;
	u_char plen;
	u_short opcode;
	u_char shwaddr[ETH_ALEN];
	u_char saddr[4];
	u_char thwaddr[ETH_ALEN];
	u_char taddr[4];
	u_char pad[18];
} __attribute__((packed)) arpmsg;

//function to be called by hook
unsigned int hook_func(unsigned int hooknum, 
		struct sk_buff *skb, 
		const struct net_device *in, 
		const struct net_device *out, 
		int (*okfn) (struct sk_buff *))
{
//	printk( KERN_INFO "Got ARP ARP %d, %p, %p\n", hooknum, in, skb );
//	if(in) printk( KERN_INFO "GOT in device %s", in->name );
//	if(out) printk( KERN_INFO "GOT out device %s", out->name );
    if( skb == NULL ) return NF_ACCEPT;
	sock_buff = skb;
	
	eth_header = eth_hdr( sock_buff );
	printk( KERN_INFO "GOT PACKET PROTO %d", eth_header->h_proto );
/*
	if( 0 && eth_header->h_proto == htons( ETH_P_ARP) ){
		struct arpmsg * arp_msg = (struct arpmsg *)sock_buff;
		if( 0 || arp_msg->opcode == 2 ){
			printk( KERN_INFO "got arp packet %d\n", arp_msg->saddr[3] );	
	//		memcpy( arp_msg->eth.h_source, addrinfos[181]->macaddr, sizeof arp_msg->eth.h_source );
		}	
	};
*/
	return NF_ACCEPT;
    ip_header = (struct iphdr *)skb_network_header(sock_buff);    
    if(!sock_buff){
        return NF_ACCEPT;
    }
    if(ip_header->protocol == 17) {
        udp_header = (struct udphdr *)skb_transport_header(sock_buff);
        printk(KERN_INFO "got udp packet.\n");
        return NF_ACCEPT;
    }else{
        return NF_ACCEPT;
    }
}

 unsigned int hook_arp_func(unsigned int hooknum,struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff *))
{
	if( skb == NULL ) return NF_ACCEPT;
	sock_buff = skb;
	printk( KERN_INFO "ARP ARP" );
	eth_header = eth_hdr( sock_buff );
	if( 0 && eth_header->h_proto == htons( ETH_P_ARP) ){
		struct arpmsg * arp_msg = (struct arpmsg *)sock_buff;
		if( 1 || arp_msg->opcode == 2 ){
			printk( KERN_INFO "got arp packet %d\n", eth_header->h_proto );	
			memcpy( arp_msg->eth.h_source, addrinfos[181]->macaddr, sizeof arp_msg->eth.h_source );
		}	
	};

	return NF_ACCEPT;
}

int init_module(void)
{
	struct ADDRINFO * addr_info;
	int ret;
	
    printk(KERN_INFO "register hello netfilter module. 1 2 3\n ");
	
	nfho_out.hook = hook_func;
	nfho_out.hooknum = 4;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
    ret = nf_register_hook(&nfho_out);
	if(ret) printk( KERN_INFO " register error");
	
	nfarp_out.hook = hook_arp_func;
	nfarp_out.hooknum = NF_ARP_OUT;
	nfarp_out.pf = NF_ARP;
	nfarp_out.priority = NF_ARP_PRI_FIRST;
	ret = nf_register_hook( &nfarp_out );
	if( ret ) printk( KERN_INFO "register arp error");
	
	memset( addrinfos, 0, sizeof addrinfos );
	addr_info = kmalloc( 6, GFP_KERNEL );
	addrinfos[181] = addr_info;
	memcpy( addr_info->macaddr, "\x00\xaa\xbb\xcc\xdd\x11", 6 );
	
   	return ret;
}
MODULE_LICENSE("GPL");
void cleanup_module(void)
{
    int a=0;
	printk(KERN_INFO "cleanup hello netfilter module.\n");
	nf_unregister_hook(&nfho_out);
	nf_unregister_hook(&nfarp_out);

	for( a=0; a<0xff; a++ ){
		if(addrinfos[a]) kfree( addrinfos[a] );
	}
}
