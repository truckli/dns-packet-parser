#ifndef TCAD_CAPTURE_HTTP_EXTRACTOR_H
#define TCAD_CAPTURE_HTTP_EXTRACTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef likely
#define likely(x)       (x)
#endif
#ifndef unlikely
#define unlikely(x)     (x)
#endif

#define HTTP_MESSAGE_TYPE_NON_HEADERS 0
#define HTTP_MESSAGE_TYPE_REQUEST_HEADERS 1
#define HTTP_MESSAGE_TYPE_RESPONSE_HEADERS 2
#define HTTP_REQUEST_METHOD_UNKNOWN 0
#define HTTP_REQUEST_METHOD_OPTIONS 1
#define HTTP_REQUEST_METHOD_GET 2
#define HTTP_REQUEST_METHOD_HEAD 3
#define HTTP_REQUEST_METHOD_POST 4
#define HTTP_REQUEST_METHOD_PUT 5
#define HTTP_REQUEST_METHOD_DELETE 6
#define HTTP_REQUEST_METHOD_TRACE 7
#define HTTP_REQUEST_METHOD_CONNECT 8
#define HTTP_VERSION_UNKNOWN 0
#define HTTP_VERSION_0_9 1
#define HTTP_VERSION_1_0 2
#define HTTP_VERSION_1_1 3
#define HTTP_VERSION_2_0 4

#define __HTTP_COMPARE_MEM1(x, y) (*((uint8_t*)(x)) == *((uint8_t*)(y)))
#define __HTTP_COMPARE_MEM2(x, y) (*((uint16_t*)(x)) == *((uint16_t*)(y)))
#define __HTTP_COMPARE_MEM3(x, y) ( __HTTP_COMPARE_MEM2(x, y) && __HTTP_COMPARE_MEM1((uint8_t*)x+2, (uint8_t*)y+2))
#define __HTTP_COMPARE_MEM4(x, y) (*((uint32_t*)(x)) == *((uint32_t*)(y)))
#define __HTTP_COMPARE_MEM5(x, y) ( __HTTP_COMPARE_MEM4(x, y) && __HTTP_COMPARE_MEM1((uint8_t*)x+4, (uint8_t*)y+4))
#define __HTTP_COMPARE_MEM6(x, y) ( __HTTP_COMPARE_MEM4(x, y) && __HTTP_COMPARE_MEM2((uint8_t*)x+4, (uint8_t*)y+4))
#define __HTTP_COMPARE_MEM7(x, y) ( __HTTP_COMPARE_MEM6(x, y) && __HTTP_COMPARE_MEM1((uint8_t*)x+6, (uint8_t*)y+6))
#define __HTTP_COMPARE_MEM8(x, y) (*((uint64_t*)(x)) == *((uint64_t*)(y)))
#define __HTTP_COMPARE_MEM9(x, y) ( __HTTP_COMPARE_MEM8(x, y) && __HTTP_COMPARE_MEM1((uint8_t*)x+8, (uint8_t*)y+8))
#define __HTTP_COMPARE_MEM10(x, y) ( __HTTP_COMPARE_MEM8(x, y) && __HTTP_COMPARE_MEM2((uint8_t*)x+8, (uint8_t*)y+8))
#define __HTTP_COMPARE_MEM11(x, y) ( __HTTP_COMPARE_MEM8(x, y) && __HTTP_COMPARE_MEM3((uint8_t*)x+8, (uint8_t*)y+8))
#define __HTTP_COMPARE_MEM12(x, y) ( __HTTP_COMPARE_MEM8(x, y) && __HTTP_COMPARE_MEM4((uint8_t*)x+8, (uint8_t*)y+8))
#define __HTTP_COMPARE_MEM13(x, y) ( __HTTP_COMPARE_MEM8(x, y) && __HTTP_COMPARE_MEM5((uint8_t*)x+8, (uint8_t*)y+8))
#define __HTTP_COMPARE_MEM14(x, y) ( __HTTP_COMPARE_MEM8(x, y) && __HTTP_COMPARE_MEM6((uint8_t*)x+8, (uint8_t*)y+8))
#define __HTTP_COMPARE_MEM15(x, y) ( __HTTP_COMPARE_MEM8(x, y) && __HTTP_COMPARE_MEM7((uint8_t*)x+8, (uint8_t*)y+8))
#define __HTTP_COMPARE_MEM16(x, y) ( __HTTP_COMPARE_MEM8(x, y) && __HTTP_COMPARE_MEM8((uint8_t*)x+8, (uint8_t*)y+8))
#define __HTTP_COMPARE_MEM24(x, y) ( __HTTP_COMPARE_MEM8(x, y) && __HTTP_COMPARE_MEM16((uint8_t*)x+8, (uint8_t*)y+8))

#define __HTTP_GET_VERSION(str, code) {\
		if (likely(__HTTP_COMPARE_MEM8(str, "HTTP/1.1"))) {\
			code = HTTP_VERSION_1_1; \
		} else if (__HTTP_COMPARE_MEM8(str, "HTTP/1.0")) {\
			code = HTTP_VERSION_1_0; \
		} else if (__HTTP_COMPARE_MEM8(str, "HTTP/2.0")) {\
			code = HTTP_VERSION_2_0; \
		} else if (__HTTP_COMPARE_MEM8(str, "HTTP/0.9")) {\
			code = HTTP_VERSION_0_9; \
		} else { \
			code = HTTP_VERSION_UNKNOWN; \
		} \
}

#define __HTTP_HEADER_USER_AGENT 0x1
#define __HTTP_HEADER_HOST 0x2
#define __HTTP_HEADER_COOKIE 0x4
#define __HTTP_HEADER_CONTENT_TYPE 0x8
#define __HTTP_HEADER_CONTENT_LENGTH 0x10
#define __HTTP_HEADER_REFERER 0x20
#define __HTTP_HEADERS_TO_EXTRACT (0x3f)
#define __HTTP_ALL_FIELDS_EXTRACTED(x) (x == __HTTP_HEADERS_TO_EXTRACT)

#define MOVE_TO_HTTP_LINE_END for (line_end = p; *line_end != '\r' && line_end != msg_end; ++line_end);

#define	__HTTP_CHECK_LINE_TRUNCATED if (unlikely((uint64_t)line_end <= (uint64_t)p)) break;


typedef struct {
	uint32_t type:2;// 0 for non-http-start, 1 for request head, 2 for response head. if equals 0, other fields are undefined
	uint32_t method:4;// 0 for unknown method, 2 for GET, 3 for HEAD, 4 for POST
	uint32_t version:3;// 0-4 for unknown version, 0.x, 1.0, 1,1, 2.0
	uint32_t l_host:8;//length of host field
	uint32_t status_code:10;//200, 404, etc
	uint32_t chunked_encoding:1;// HTTP chunked encoding
	uint16_t l_user_agent;//length of user-agent
	uint16_t l_cookie;//length of cookie
	uint16_t l_url;
	uint16_t l_content_type;
	uint16_t l_referer;
	uint32_t content_length;
	uint8_t *p_host;//start address of host field value after colon(:) and a space
	uint8_t *p_user_agent;
	uint8_t *p_cookie;
	uint8_t *p_url;
	uint8_t *p_content_type;
	uint8_t *p_referer;
} __attribute__ ((aligned(8))) http_access_info_t;

static void extract_http_access_info(uint8_t *msg, size_t len, http_access_info_t *access)
{
	/*minimum request: GET / HTTP/1.1\r\n */
	if (unlikely(!msg || len < 16 || !access)) {
		access->type = HTTP_MESSAGE_TYPE_NON_HEADERS;
		return;
	}

	if (unlikely(__HTTP_COMPARE_MEM4(msg, "HTTP"))) {
		access->type = HTTP_MESSAGE_TYPE_RESPONSE_HEADERS;
	} else if (unlikely(__HTTP_COMPARE_MEM4(msg, "GET "))) {
		access->type = HTTP_MESSAGE_TYPE_REQUEST_HEADERS;
		access->method = HTTP_REQUEST_METHOD_GET;
		access->p_url = msg + sizeof("GET");
	} else if (unlikely(__HTTP_COMPARE_MEM5(msg, "POST "))) {
		access->type = HTTP_MESSAGE_TYPE_REQUEST_HEADERS;
		access->method = HTTP_REQUEST_METHOD_POST;
		access->p_url = msg + sizeof("POST");
	} else if (unlikely(__HTTP_COMPARE_MEM5(msg, "HEAD "))) {
		access->type = HTTP_MESSAGE_TYPE_REQUEST_HEADERS;
		access->method = HTTP_REQUEST_METHOD_HEAD;
		access->p_url = msg + sizeof("HEAD");
	} else if (unlikely(__HTTP_COMPARE_MEM4(msg, "PUT "))) {
		access->type = HTTP_MESSAGE_TYPE_REQUEST_HEADERS;
		access->method = HTTP_REQUEST_METHOD_PUT;
		access->p_url = msg + sizeof("PUT");
	} else {
		access->type = HTTP_MESSAGE_TYPE_NON_HEADERS;
		return;
	}

	uint8_t *p, *msg_end, *line_end;
	msg_end = msg + len;

	/*
	 * move p to end of request line, at least 14 characters
	 */
	p = msg + 14;
	MOVE_TO_HTTP_LINE_END;
	if (unlikely(line_end == msg_end)) {//first line incomplete
		access->type = HTTP_MESSAGE_TYPE_NON_HEADERS;
		return;
	}

	access->l_content_type = 0;
	access->p_content_type = NULL;
	access->content_length = 0;
	access->chunked_encoding = 0;

	if (access->type == HTTP_MESSAGE_TYPE_RESPONSE_HEADERS) {
		__HTTP_GET_VERSION(msg, access->version);
		if (likely(__HTTP_COMPARE_MEM4(msg+8, " 200"))) {
			access->status_code = 200;
		} else {
			access->status_code = (msg[9]-'0')*100 + (msg[10]-'0')*10 + msg[11]-'0';
		}
	} else {//HTTP Request
		access->l_host = 0;
		access->p_host = NULL;
		access->l_user_agent = 0;
		access->p_user_agent = NULL;
		access->l_cookie = 0;
		access->p_cookie = NULL;
		access->l_referer = 0;
		access->p_referer = NULL;
		__HTTP_GET_VERSION(line_end-8, access->version);
		access->l_url = line_end - 9 - access->p_url;
	}

	if (access->version == HTTP_VERSION_UNKNOWN) {
		access->type = HTTP_MESSAGE_TYPE_NON_HEADERS;
		return;
	}

	uint32_t extracted_headers = 0;
	p = line_end + 2;
	while (p-msg < len) {
		MOVE_TO_HTTP_LINE_END;
		if (unlikely(line_end == p)) break;//End-of-Headers
		if (unlikely(__HTTP_COMPARE_MEM12(p, "User-Agent: "))) {
			p += sizeof("User-Agent:");
			__HTTP_CHECK_LINE_TRUNCATED
			access->p_user_agent = p;
			access->l_user_agent = line_end - p;
			extracted_headers |= __HTTP_HEADER_USER_AGENT;
			if (__HTTP_ALL_FIELDS_EXTRACTED(extracted_headers)) break;
		} else if (unlikely(__HTTP_COMPARE_MEM6(p, "Host: "))) {
			p += sizeof("Host:");
			__HTTP_CHECK_LINE_TRUNCATED
			access->p_host = p;
			access->l_host = line_end - p;
			extracted_headers |= __HTTP_HEADER_HOST;
			if (__HTTP_ALL_FIELDS_EXTRACTED(extracted_headers)) break;
		} else if (unlikely(__HTTP_COMPARE_MEM8(p, "Cookie: "))) {
			p += sizeof("Cookie:");
			__HTTP_CHECK_LINE_TRUNCATED
			access->p_cookie = p;
			access->l_cookie = line_end - p;
			extracted_headers |= __HTTP_HEADER_COOKIE;
			if (__HTTP_ALL_FIELDS_EXTRACTED(extracted_headers)) break;
		} else if (unlikely(__HTTP_COMPARE_MEM9(p, "Referer: "))) {
			p += sizeof("Referer:");
			__HTTP_CHECK_LINE_TRUNCATED
			access->p_referer = p;
			access->l_referer = line_end - p;
			extracted_headers |= __HTTP_HEADER_REFERER;
			if (__HTTP_ALL_FIELDS_EXTRACTED(extracted_headers)) break;
		} else if (unlikely(__HTTP_COMPARE_MEM14(p, "Content-Type: "))) {
			p += sizeof("Content-Type:");
			__HTTP_CHECK_LINE_TRUNCATED
			access->p_content_type = p;
			access->l_content_type = line_end - p;
			extracted_headers |= __HTTP_HEADER_CONTENT_TYPE;
			if (__HTTP_ALL_FIELDS_EXTRACTED(extracted_headers)) break;
		} else if (unlikely(__HTTP_COMPARE_MEM16(p, "Content-Length: "))) {
			p += sizeof("Content-Length:");
			__HTTP_CHECK_LINE_TRUNCATED
			access->content_length = *p++ - '0';
			while (p != line_end) access->content_length = access->content_length * 10 + *p++ - '0';
			extracted_headers |= __HTTP_HEADER_CONTENT_LENGTH;
			if (__HTTP_ALL_FIELDS_EXTRACTED(extracted_headers)) break;
		} else if (unlikely(__HTTP_COMPARE_MEM24(p, "Transfer-Encoding: chunked"))) {
			access->chunked_encoding = 1;
			extracted_headers |= __HTTP_HEADER_CONTENT_LENGTH;
			if (__HTTP_ALL_FIELDS_EXTRACTED(extracted_headers)) break;
		}

		p = line_end + 2;
	}

	if (access->chunked_encoding && p == line_end && p-msg < len-4) {//Parse 1st chunk of HTTP chunked encoding
		p = line_end + 2;
		MOVE_TO_HTTP_LINE_END;
		if (line_end != msg_end) {//Parse a hexadecimal value
			access->content_length = 0;
			while (p != line_end) {
				access->content_length <<= 4;
				if (*p >= '0' && *p <= '9') {
					access->content_length += *p - '0';
				} else if (*p >= 'A' && *p <= 'F') {
					access->content_length += *p - 'A' + 10;
				} else if (*p >= 'a' && *p <= 'f') {
					access->content_length += *p - 'a' + 10;
				}
				p++;
			}
		} else {
		}
	}

}

#ifdef __cplusplus
}
#endif

#endif
