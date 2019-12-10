/*
 * analysis.c
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */


#include <arpa/inet.h>
#include "analysis.h"
#include "ept.h"

#include <iostream>
#include <fstream>
#include <math.h>

#include "nlohmann/json.hpp"
using json = nlohmann::json;
json fp_db;


enum analysis_cfg analysis_cfg = analysis_off;

int database_init() {
    json fp;


    std::ifstream in_file("resources/fingerprint_db.json");
    std::string line;
    while(getline(in_file, line)) {
        fp = json::parse(line);
        fp_db[(std::string)fp["str_repr"]] = fp;
    }

    return 1;
}


int analysis_init() {
    extern enum analysis_cfg analysis_cfg;
    analysis_cfg = analysis_on;

    database_init();
    return 1;
}

int analysis_finalize() {
    extern enum analysis_cfg analysis_cfg;
    analysis_cfg = analysis_off;
    return 1;
}

#define SNI_HEADER_LEN 9

#define MAX_DST_ADDR_LEN 40
void flow_key_sprintf_dst_addr(const struct flow_key *key,
			       char *dst_addr_str) {

    if (key->type == ipv4) {
	uint8_t *d = (uint8_t *)&key->value.v4.dst_addr;
	snprintf(dst_addr_str,
		 MAX_DST_ADDR_LEN,
		 "%u.%u.%u.%u",
		 d[0], d[1], d[2], d[3]);
    } else if (key->type == ipv6) {
	uint8_t *d = (uint8_t *)&key->value.v6.dst_addr;
	snprintf(dst_addr_str,
		 MAX_DST_ADDR_LEN,
		 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		 d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
    }
}



std::string get_asn_info(char* dst_ip) {
    return "14618:Amazon.com";
}

std::string get_port_app(uint16_t dst_port) {
    return "https";
}

std::string get_domain_name(char* server_name) {
    return "cisco.com";
}




#define MAX_FP_STR_LEN 4096
#define MAX_SNI_LEN     257
void fprintf_analysis_from_extractor_and_flow_key(FILE *file,
						  const struct extractor *x,
						  const struct flow_key *key) {
    json fp;
    extern enum analysis_cfg analysis_cfg;

    if (analysis_cfg == analysis_off) {
        return; // do not perform any analysis
    }

    if (x->fingerprint_type == fingerprint_type_tls) {
        char dst_ip[MAX_DST_ADDR_LEN];
        unsigned char fp_str[MAX_FP_STR_LEN];
        char server_name[MAX_SNI_LEN];
        uint16_t dst_port = 0;

        uint8_t *extractor_buffer = x->output_start;
        size_t bytes_extracted = extractor_get_output_length(x);
        sprintf_binary_ept_as_paren_ept(extractor_buffer, bytes_extracted, fp_str, MAX_FP_STR_LEN); // should check return result
        flow_key_sprintf_dst_addr(key, dst_ip);
        if (x->packet_data.type == packet_data_type_tls_sni) {
            size_t sni_len = x->packet_data.length - SNI_HEADER_LEN;
            sni_len = sni_len > MAX_SNI_LEN-1 ? MAX_SNI_LEN-1 : sni_len;
            memcpy(server_name, x->packet_data.value + SNI_HEADER_LEN, sni_len);
            server_name[sni_len] = 0; // null termination
        }

        fp = fp_db[std::string((char*)fp_str)];
        if (fp == NULL) {
            return; // no match
        }

        std::string asn = get_asn_info(dst_ip);
        std::string port_app = get_port_app(dst_port);
        std::string domain = get_domain_name(server_name);

        uint32_t fp_tc, p_count, tmp_value;
        long double prob_process_given_fp, score;
        long double max_score = -1.0;
        long double score_sum = 0.0;
        json max_proc, equiv_class;

        long double base_prior = -18.42068;
        long double prior      =  -4.60517;

        fp_tc = fp["total_count"].get<uint32_t>();
        for (json::iterator it = fp["process_info"].begin(); it != fp["process_info"].end(); ++it) {
            p_count = (*it)["count"].get<uint32_t>();
            prob_process_given_fp = (long double)p_count/fp_tc;


            score = log(prob_process_given_fp);
            score = fmax(score, base_prior);

            equiv_class = (*it)["classes_ip_as"];
            if (equiv_class[asn].is_null()) {
                score += base_prior;
            } else {
                tmp_value = equiv_class[asn];
                score += fmax(log((long double)tmp_value/p_count), prior);
            }

            equiv_class = (*it)["classes_hostname_domains"];
            if (equiv_class[domain].is_null()) {
                score += base_prior;
            } else {
                tmp_value = equiv_class[domain];
                score += fmax(log((long double)tmp_value/p_count), prior);
            }

            equiv_class = (*it)["classes_port_applications"];
            if (equiv_class[port_app].is_null()) {
                score += base_prior;
            } else {
                tmp_value = equiv_class[port_app];
                score += fmax(log((long double)tmp_value/p_count), prior);
            }

            score = exp(score);
            score_sum += score;

            if (score > max_score) {
                max_score = score;
                max_proc = *it;
            }
        }

        if (score_sum > 0.0) {
            max_score /= score_sum;
        }

        fprintf(file, "\"analysis\":{\"process\":\"%s\",\"score\":%Lf},", max_proc["process"].get<std::string>().c_str(), max_score);

    }

}





/*
 * analysis_cfg is a global variable that configures the analysis
 */
/*
enum analysis_cfg analysis_cfg = analysis_off;

#ifdef HAVE_PYTHON3

#include "python_interface.h"

int analysis_init() {
    extern enum analysis_cfg analysis_cfg;
    analysis_cfg = analysis_on;
    return init_python();
}

int analysis_finalize() {
    extern enum analysis_cfg analysis_cfg;
    analysis_cfg = analysis_off;
    return finalize_python();
}

#define SNI_HEADER_LEN 9

#define MAX_DST_ADDR_LEN 40
void flow_key_sprintf_dst_addr(const struct flow_key *key,
			       char *dst_addr_str) {
 
    if (key->type == ipv4) {
	uint8_t *d = (uint8_t *)&key->value.v4.dst_addr;
	snprintf(dst_addr_str,
		 MAX_DST_ADDR_LEN,
		 "%u.%u.%u.%u",
		 d[0], d[1], d[2], d[3]);		
    } else if (key->type == ipv6) {
	uint8_t *d = (uint8_t *)&key->value.v6.dst_addr;
	snprintf(dst_addr_str,
		 MAX_DST_ADDR_LEN,
		 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		 d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
    }
}

#define MAX_FP_STR_LEN 4096
#define MAX_SNI_LEN     257
void fprintf_analysis_from_extractor_and_flow_key(FILE *file,
						  const struct extractor *x,
						  const struct flow_key *key) {
    //struct results_obj *r_p;
    char *r_p;
    extern enum analysis_cfg analysis_cfg;

    if (analysis_cfg == analysis_off) {
	return; // do not perform any analysis
    }
    
    if (x->fingerprint_type == fingerprint_type_tls) {
	char dst_addr_string[MAX_DST_ADDR_LEN];
	unsigned char fp_string[MAX_FP_STR_LEN];
	char tmp_sni[MAX_SNI_LEN];
	uint16_t dest_port = 0;
	
	uint8_t *extractor_buffer = x->output_start;
	size_t bytes_extracted = extractor_get_output_length(x);
	sprintf_binary_ept_as_paren_ept(extractor_buffer, bytes_extracted, fp_string, MAX_FP_STR_LEN); // should check return result
	flow_key_sprintf_dst_addr(key, dst_addr_string);
	if (x->packet_data.type == packet_data_type_tls_sni) {
	    size_t sni_len = x->packet_data.length - SNI_HEADER_LEN;
	    sni_len = sni_len > MAX_SNI_LEN-1 ? MAX_SNI_LEN-1 : sni_len;
	    memcpy(tmp_sni, x->packet_data.value + SNI_HEADER_LEN, sni_len);
	    tmp_sni[sni_len] = 0; // null termination
	}
	
	fprintf(file, "\"analysis\":");
	py_process_detection(&r_p, (char *)fp_string, tmp_sni, dst_addr_string, dest_port);
	fprintf(file, "%s", r_p);
	fprintf(file, ",");
    }

}

#else // HAVE_PYTHON3 is not defined

int analysis_init() {
    fprintf(stderr, "error: analysis requested, but analysis engine not present\n"); 
    return -1; 
}

int analysis_finalize() {
    // nothing to do
    return -1;
}

void fprintf_analysis_from_extractor_and_flow_key(FILE *file,
						  const struct extractor *x,
						  const struct flow_key *key) {
    (void)file; // unused
    (void)x;    // unused
    (void)key;  // unused
}


#endif // HAVE_PYTHON3
*/

