/*
 * testcases.cpp
 *
 *  Created on: 2015年12月2日
 *      Author: mz
 */
#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "netinet/ip.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include "arpa/inet.h"

using namespace std;
#include "debug-helper.h"
#include "http-extractor.h"
#include "dns-extractor.h"


//defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

typedef unsigned char uc;

char debug_buf[2048];

#define test_print_plv(x) {\
		if (access->p_ ## x && access->l_ ## x > 0) {\
			string pval((const char* )access->p_ ## x, (size_t)access->l_ ## x);\
			cout << #x << "(" << dec << (size_t)access->l_ ## x << " bytes)=" << pval << "; ";\
		} else { \
			cout << #x << " field missing; "; \
		} \
}

void test_print_dns_access_info(const dns_access_info_t *access)
{
	SHOWHEX(access->dns_id);
	SHOW(access->rd);
	SHOW(access->ra);
	SHOW(access->qr);
	SHOW(access->aa);
	SHOW(access->rcode);
	SHOW(access->qtype);
	SHOW(access->rrtype);
	SHOW(access->ttl);
	SHOW(access->l_value);
	test_print_plv(domain);
	SHOWHBUF(access->p_value, access->l_value);

	cout << " *********" << endl;
}

void test_print_http_access_info(const http_access_info_t *access)
{
	cout << " *********  " ;
	if (access->type == 0) {
		cout << "Not a HTTP head." <<endl;
		return;
	} else if (access->type == 1) {
		cout << "HTTP Request; ";
		test_print_match_val(access->method, HTTP_REQUEST_METHOD_UNKNOWN);
		test_print_match_val(access->method, HTTP_REQUEST_METHOD_OPTIONS);
		test_print_match_val(access->method, HTTP_REQUEST_METHOD_GET);
		test_print_match_val(access->method, HTTP_REQUEST_METHOD_HEAD);
		test_print_match_val(access->method, HTTP_REQUEST_METHOD_POST);
		test_print_match_val(access->method, HTTP_REQUEST_METHOD_PUT);
		test_print_match_val(access->method, HTTP_REQUEST_METHOD_DELETE);
		test_print_match_val(access->method, HTTP_REQUEST_METHOD_TRACE);
		test_print_match_val(access->method, HTTP_REQUEST_METHOD_CONNECT);
		test_print_plv(url);
		test_print_plv(cookie);
		test_print_plv(host);
		test_print_plv(user_agent);
		test_print_plv(referer);
	} else {
		cout << "HTTP Response; ";
        SHOW(access->status_code);
	}

	test_print_match_val(access->version, HTTP_VERSION_UNKNOWN);
	test_print_match_val(access->version, HTTP_VERSION_0_9);
	test_print_match_val(access->version, HTTP_VERSION_1_0);
	test_print_match_val(access->version, HTTP_VERSION_1_1);
	test_print_match_val(access->version, HTTP_VERSION_2_0);
	test_print_plv(content_type);
	SHOW(access->content_length);
	SHOW(access->chunked_encoding);

	cout << " *********" << endl;

}

void testcase_mem_cmp()
{
	assert(__HTTP_COMPARE_MEM1("a2", "a3"));
    assert(!__HTTP_COMPARE_MEM1("a2", "b3"));
    assert(__HTTP_COMPARE_MEM2("a235", "a234"));
    assert(!__HTTP_COMPARE_MEM4("a235", "a234"));
    assert(__HTTP_COMPARE_MEM4("12345", "12346"));
    assert(__HTTP_COMPARE_MEM6("123456y", "123456x"));
    assert(!__HTTP_COMPARE_MEM6("123455y", "123466x"));
    assert(__HTTP_COMPARE_MEM8("12345678y", "12345678x"));
    assert(!__HTTP_COMPARE_MEM8("12345678y", "12345677x"));
    assert(__HTTP_COMPARE_MEM3("12345678y", "12355677x"));
    assert(!__HTTP_COMPARE_MEM3("12345678y", "12245677x"));
}


void testcase_http_manually()
{
	http_access_info_t access;
	const char *http_msg;

	http_msg =
			"HTTP/1.0 556 SOME STATUS\r\n"
			"Some-Header: some-val\r\n"
			"Set-Cookie: some-cookie \r\n"
			"Transfer-Encoding: chunked\r\n\r\nAf3d\r\n";

	extract_http_access_info((uint8_t*)http_msg, strlen(http_msg), &access);
	test_print_http_access_info(&access);

	http_msg =
			"GET / HTTP/0.9\r\n"
			"Some-Header: some-val\r\n"
			"Cookie: some-cookie\r\n"
			"Host: some-host\r\n";

	extract_http_access_info((uint8_t*)http_msg, strlen(http_msg), &access);
	test_print_http_access_info(&access);

	http_msg =
			"GET / HTTP/0.9\r\n"
			"Cookie: some-cookie\r\n"
			"Some-Header: some-val\r\n\r\n" //test end-of-headers
			"Host: some-host\r\n";

	extract_http_access_info((uint8_t*)http_msg, strlen(http_msg), &access);
	test_print_http_access_info(&access);


	http_msg =
			"GET / HTTP/1.0\r\n"
			"Some-Header: some-val\r\n"
			"Cookie: some-cookie \r\n"
			"Host: some-host\r\n";

	extract_http_access_info((uint8_t*)http_msg, strlen(http_msg), &access);
	test_print_http_access_info(&access);

	http_msg =
			"HTTP/1.0 556 SOME STATUS\r\n"
			"Some-Header: some-val\r\n"
			"Cookie: some-cookie \r\n"
			"Host: some-host\r\n";

	extract_http_access_info((uint8_t*)http_msg, strlen(http_msg), &access);
	test_print_http_access_info(&access);

	http_msg =
			"PUT /some-url HTTP/2.0\r\n"
			"Some-Header: some-val\r\n"
			"Cookie: some-cookie \r\n"
			"Referer: some-referer\r\n"
			"Content-Length: 104\r\n"
			"Host: host.com\r\n";

	extract_http_access_info((uint8_t*)http_msg, strlen(http_msg), &access);
	test_print_http_access_info(&access);
}

void test_parse_pcap(pcap_t *handle)
{
	uc *packet; // The actual packet
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	while (true) {
		packet = (uc *)pcap_next(handle,&header);
		if (!packet) break;
		uc *pkt_ptr = (uc *)packet; //cast a pointer to the packet data

		//parse the first (ethernet) header, grabbing the type field
		int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];
		int ether_offset = 0;

		if (ether_type == ETHER_TYPE_IP) //most common
			ether_offset = 14;
		else if (ether_type == ETHER_TYPE_8021Q) //my traces have this
			ether_offset = 18;
		else {
		//	fprintf(stderr, "Unknown ethernet type, %04X, skipping...\n", ether_type);
			ether_offset = 16;
		}

		//parse the IP header
		pkt_ptr += ether_offset;  //skip past the Ethernet II header
		struct ip *ip_hdr = (struct ip *)pkt_ptr; //point to an IP header structure

		int packet_length = ntohs(ip_hdr->ip_len);
		int ip_header_len = ((ip_hdr->ip_hl)<<2);
		uc *level4_segment = pkt_ptr + ip_header_len;
		uint16_t sport, dport;

		if (ip_hdr->ip_p == IPPROTO_UDP) {
			struct udphdr *udp_hdr;
			udp_hdr = (struct udphdr *)level4_segment;
			sport = ntohs(udp_hdr->uh_sport);
			dport = ntohs(udp_hdr->uh_dport);
			int payload_len = ntohs(udp_hdr->uh_ulen) - 8;
			if (sport == 53 || dport == 53) {
				string message((const char *)(level4_segment + 8), payload_len);
				dns_access_info_t access;
				extract_dns_access_info((uint8_t *)message.c_str(), message.size(), &access);
				test_print_dns_access_info(&access);
			}
		} else if (ip_hdr->ip_p == IPPROTO_TCP) {
			struct tcphdr *tcp_hdr = (struct tcphdr *)level4_segment;
			sport = ntohs(tcp_hdr->th_sport);
			dport = ntohs(tcp_hdr->th_dport);
			int tcp_header_len = tcp_hdr->th_off << 2;
			int payload_len = packet_length - ip_header_len - tcp_header_len;
			if (payload_len == 0) continue;
			string http_message((const char *)(level4_segment + tcp_header_len), payload_len);
			if (dport == 80 || sport == 80) {
				http_access_info_t access;
				extract_http_access_info((uint8_t *)http_message.c_str(), http_message.size(), &access);
				test_print_http_access_info(&access);
			}
		}


	}
}

void testcase_http_offline_pcap()
{
	struct pcap_pkthdr header; // The header that pcap gives us
    pcap_t *handle;

    char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well
    const char *pcap_fname = "http.pcap";
    handle = pcap_open_offline(pcap_fname, errbuf);   //call pcap library function

    if (handle == NULL) {
      fprintf(stderr,"Couldn't open pcap file %s: %s\n", pcap_fname, errbuf);
      return;
    }

    test_parse_pcap(handle);
    pcap_close(handle);  //close the pcap file
}

void testcase_dns_offline_pcap()
{
	struct pcap_pkthdr header; // The header that pcap gives us
    pcap_t *handle;

    char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well

    handle = pcap_open_offline("dns1.pcap", errbuf);   //call pcap library function
    if (handle) {
    	test_parse_pcap(handle);
    	pcap_close(handle);  //close the pcap file
    }

    handle = pcap_open_offline("dns2.pcap", errbuf);   //call pcap library function
    if (handle) {
    	test_parse_pcap(handle);
    	pcap_close(handle);  //close the pcap file
    }

    handle = pcap_open_offline("dns3.pcap", errbuf);   //call pcap library function
    if (handle) {
    	test_parse_pcap(handle);
    	pcap_close(handle);  //close the pcap file
    }

    handle = pcap_open_offline("dns4.pcap", errbuf);   //call pcap library function
    if (handle) {
    	test_parse_pcap(handle);
    	pcap_close(handle);  //close the pcap file
    }
}




int testcase_http_online_pcap()
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	u_char *packet;		/* The actual packet */

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
    test_parse_pcap(handle);
    pcap_close(handle);  //close the pcap file
    return 0;
}

int main(int argc, char **argv)
{
	testcase_dns_offline_pcap();
	testcase_http_offline_pcap();
	return 0;
}
