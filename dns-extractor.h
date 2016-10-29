#ifndef TCAD_CAPTURE_DNS_EXTRACTOR_H
#define TCAD_CAPTURE_DNS_EXTRACTOR_H

/*
 * This module extracts some useful data from a DNS message.
 *
 * for introduction of DNS types, see:
 *  https://en.wikipedia.org/wiki/List_of_DNS_record_types
 *
 * for specification of DNS message format, see:
 * 	https://tools.ietf.org/html/rfc1034
 * 	https://tools.ietf.org/html/rfc1035
 */


#ifdef __cplusplus
extern "C" {
#endif

#ifndef likely
#define likely(x)       (x)
#endif
#ifndef unlikely
#define unlikely(x)     (x)
#endif
#ifndef min
#define min(x, y) ((x)<(y))?(x):(y)
#endif


typedef struct {
	uint32_t qr:1; // 0 for query, 1 for response
	uint32_t rd:1; // recursion desired
	uint32_t ra:1; // recursion available
	uint32_t aa:1; // authoritative answer
	uint32_t rcode:4; // return code
	uint32_t dns_id:16;//query identification
	uint32_t qtype:16;//query id
	uint32_t rrtype:16;//rr type
	uint16_t l_domain;//length of valid data in p_domain(see below)
	uint16_t l_value;//length of valid data in p_value(see below)
	uint32_t ttl;//expiration time of rr data
#define DNS_EXTRACTOR_DOMAIN_LEN_MAX 256
	uint8_t p_domain[DNS_EXTRACTOR_DOMAIN_LEN_MAX];//domain name
#define DNS_EXTRACTOR_VALUE_LEN_MAX 256
	uint8_t p_value[DNS_EXTRACTOR_VALUE_LEN_MAX];//rr answer data
} __attribute__ ((aligned(8))) dns_access_info_t;

typedef struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t rd:1;
	uint8_t tc:1;
	uint8_t aa:1;
	uint8_t opcode:4;
	uint8_t qr:1;
	uint8_t rcode:4;
	uint8_t zero:3;
	uint8_t ra:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t qr:1;
	uint8_t opcode:4;
	uint8_t aa:1;
	uint8_t tc:1;
	uint8_t rd:1;
	uint8_t ra:1;
	uint8_t zero:3;
	uint8_t rcode:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
}__dns_flag_t;


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p) (((*(uint8_t*)(p))<<8) | (*((uint8_t*)(p)+1)))
#define __DNS_EXTRACTOR_ASSIGH_VAR4_FROM_PKT(p) (((*(uint8_t*)(p))<<24) | ((*((uint8_t*)(p)+1))<<16) | ((*((uint8_t*)(p)+2))<<8) | (*((uint8_t*)(p)+3)))
#else
#define __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p) *(uint16_t*)p
#define __DNS_EXTRACTOR_ASSIGH_VAR4_FROM_PKT(p) *(uint32_t*)p
#endif


#define __DNS_EXTRACTOR_SKIP_N(p, nskip) { (p) += (nskip); if (unlikely((uint64_t)p >= (uint64_t)msg_end)) return;/*check against out-of-bound*/ }

#define __DNS_EXTRACTOR_SKIP_DOMAIN_NAME(p) { while(*p && *p < 192) __DNS_EXTRACTOR_SKIP_N(p, *p+1); if (*p) __DNS_EXTRACTOR_SKIP_N(p, 2); }

#define __DNS_EXTRACTOR_SKIP_QUESTION(p) { __DNS_EXTRACTOR_SKIP_DOMAIN_NAME(p); __DNS_EXTRACTOR_SKIP_N(p, 4); }

#define __DNS_EXTRACTOR_EXTRACT_DOMAIN_NAME(from, to, len, maxlen, msg) {\
		if (msg_end - from < 6/*min query section len*/) return;/*if domain name truncated*/ \
		uint8_t domain_compressed = 0; \
		uint8_t *p_rd = from; \
		uint8_t *p_wr = to; \
		while (*p_rd) { \
			if (*p_rd >= 192) { \
				if (!domain_compressed) { \
					__DNS_EXTRACTOR_SKIP_N(from, 2);\
					domain_compressed = 1; \
				} \
				uint16_t offset = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p_rd) - 49152; \
				p_rd = msg;\
				__DNS_EXTRACTOR_SKIP_N(p_rd, offset);\
			} else { \
				uint8_t label_len = *p_rd++; \
				if (msg_end - p_rd < (label_len + 1)) return;/*truncated*/\
				if (!domain_compressed) __DNS_EXTRACTOR_SKIP_N(from, label_len + 1); \
				uint32_t left_octets_wr = maxlen - (p_wr - to); \
				label_len = min(label_len, left_octets_wr); \
				while (label_len-- > 0) *p_wr++ = *p_rd++; \
				*p_wr++ = '.'; \
			} \
		} \
		if (!domain_compressed) __DNS_EXTRACTOR_SKIP_N(from, 1);/*skip last zero-length label '0'*/ \
		if (p_wr != to) p_wr--;/*trim trailing dot as conventional*/ \
		len = p_wr - to; \
}



static void extract_dns_access_info(uint8_t *msg, size_t len, dns_access_info_t *access)
{
/*
 * DNS id, flags, answer counts : 12 bytes
 * minimum length of domain name: set to 2
 * minimum length of query section: 2+4=6
 * minimum length of answer section: 2+8+2+0=12
 * minimum query message length: 12 + 6 = 18
 * minimum response message length: 12 + 6 + 12 = 30
 * */
	if (unlikely(!msg || len < 18)) {
		access->dns_id = 0;
		return;
	}

	access->dns_id = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(msg);
	__dns_flag_t *flags = (__dns_flag_t*)(msg+2);
	access->rd = flags->rd;
	access->ra = flags->ra;
	access->qr = flags->qr;
	access->aa = flags->aa;
	access->rcode = flags->rcode;

    uint8_t *p = msg + 4;
	uint16_t n_questions = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p);
	p += 2;
	uint16_t n_answers = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p);
	uint8_t *msg_end = msg + len;

	access->l_domain = 0;
	access->l_value = 0;
    p = msg + 12;
	if (n_questions) {
		__DNS_EXTRACTOR_EXTRACT_DOMAIN_NAME(p, access->p_domain, access->l_domain, DNS_EXTRACTOR_DOMAIN_LEN_MAX, msg);
		access->qtype = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p);
		p += 4;
		while (n_questions-- > 1) __DNS_EXTRACTOR_SKIP_QUESTION(p);
	} else {
		access->qtype = 0;
		access->rrtype = 0;
		access->ttl = 0;
		return; //no question section
	}

	if (!n_answers) {
		access->rrtype = 0;
		access->ttl = 0;
		return;
	}

	/*min domain name len: 2; min rr len:12*/
	int answer_id;
	int first_answer = -1;//first answer rr with rrtype == qtype
	uint8_t *answer_start = p;
	for (answer_id = 0; answer_id < n_answers && p-msg+12 < len; ++answer_id) {
		__DNS_EXTRACTOR_SKIP_DOMAIN_NAME(p);
		uint16_t rrtype = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p);
		if (rrtype == access->qtype) {
			first_answer = answer_id;
			break;
		}
		p += 8;//skip rrtype, class, ttl
		p += __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p) + 2;
		__DNS_EXTRACTOR_SKIP_N(p, 0);//out-of-range check
	}

	p = answer_start;
	for (answer_id = 0; answer_id < n_answers && p-msg+12 < len; ++answer_id) {
		__DNS_EXTRACTOR_SKIP_DOMAIN_NAME(p);
		uint16_t rrtype = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p);
		if (rrtype != access->qtype && first_answer >= 0) { //skip irrelevant rr
			p += 8;//skip rrtype, class, ttl
			p += __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p)+2;
			continue;
		}
		access->rrtype = rrtype;
		if (answer_id == first_answer || first_answer == -1) {
			p += 4;//skip rrtype and class
			access->ttl = __DNS_EXTRACTOR_ASSIGH_VAR4_FROM_PKT(p);
			p += 4;//skip ttl
		} else {
			p += 8;
		}
		uint16_t rdata_len = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p);
		p += 2;//skip rdata_len

		uint8_t *p_value = access->p_value + access->l_value;
		uint16_t left_octets_rd = len - (p-msg), left_octets_wr = sizeof(access->p_value) - access->l_value - 1;
		if (answer_id != first_answer && first_answer >= 0 && left_octets_wr > 0) *p_value++ = ';';
		rdata_len = min(rdata_len, left_octets_rd);

		/*for type 2,5,6,12,15, rdata is a domain name. consider create a bitmap 0x9064*/
		if (unlikely(rrtype == 15/*MX*/)) {
			p += 2;//skip preference
			uint16_t l_value;
			__DNS_EXTRACTOR_EXTRACT_DOMAIN_NAME(p, p_value, l_value, left_octets_wr, msg);
			p_value += l_value;
		} else if (unlikely(rrtype == 2/*NS*/ || rrtype == 12 /*PTR*/ || rrtype == 5/*CNAME*/ || rrtype == 6/*SOA*/)){
			uint16_t l_value;
			__DNS_EXTRACTOR_EXTRACT_DOMAIN_NAME(p, p_value, l_value, left_octets_wr, msg);
			p_value += l_value;
		} else {
			rdata_len = min(rdata_len, left_octets_wr);
			while (rdata_len-- > 0) *p_value++ = *p++;
		}
		access->l_value = p_value - access->p_value;

		if (first_answer == -1) break;
	}
}

#ifdef __cplusplus
}
#endif

#endif
