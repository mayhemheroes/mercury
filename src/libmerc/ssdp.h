/*
 * ssdp.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */


#ifndef SSDP_H
#define SSDP_H

#include "json_object.h"
#include "match.h"
#include "http.h"

/*
 * ssdp
 *
 * Reference : RFC https://datatracker.ietf.org/doc/html/draft-cai-ssdp-v1-01 (outdated)
 *           : UPnP Device Architecture Spec http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf
 *           : UpnP Device Architecture Spec (updated) https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf
 */

class ssdp {

    enum msg_type {
        notify          = 0,
        m_search        = 1,
        response        = 2,
        max_msg_type    = 3
    };

    static constexpr const char* msg_str[max_msg_type] = {"notify", "m_search", "response"};

    struct datum method;
    struct http_headers headers;
    struct perfect_hash_visitor &ph_visitor;
    enum msg_type type;

    void set_msg_type (datum &p) {
        uint8_t msg;
        p.lookahead_uint8(&msg);

        switch (msg)
        {
        case 'N':
            type = notify;
            break;
        case 'M':
            type = m_search;
            break;
        case 'H':
            type = response;
            break;
        default:
            type = max_msg_type;
            break;
        }

        return;
    }

public:

    ssdp(datum &p, perfect_hash_visitor &visitor) : method{NULL, NULL}, headers{}, ph_visitor{visitor}, type{max_msg_type} { parse(p); }

    void parse(datum &p) {
        set_msg_type(p);

        method.parse_up_to_delim(p, '\n');
        method.trim_trail('\r');
        p.skip(1);

        /* parse the headers */
        headers.parse_ignore_cr(p);

        return;
    }

    bool is_not_empty() const { return (type != max_msg_type); }

    void write_json(struct json_object &record, bool output_metadata) {
        if (this->is_not_empty()) {
            struct json_object ssdp{record, "ssdp"};
            struct json_object msg{ssdp, msg_str[type]};

            // run the list of http headers to be printed out against
            // all headers, and print the values corresponding to each
            // of the matching names
            //
            if (output_metadata) {
                msg.print_key_json_string("method", method);
            }
            headers.print_matching_names_ssdp(msg, ph_visitor, perfect_hash_table_type::HTTP_SSDP_HEADERS,output_metadata);

            msg.close();
            ssdp.close();
        }

        return;
    }

    /*
     *    Matchers for ssdp msg types
     *    static constexpr mask_and_value<8> matcher_notify{
     *        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00 },
     *        { 'N',  'O',  'T',  'I',  'F', 'Y', 0x00, 0x00 }
     *   };
     *
     *    static constexpr mask_and_value<8> matcher_search{
     *        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
     *        { 'M',  '-',  'S',  'E',  'A', 'R', 'C', 'H' }
     *    };
     *
     *    static constexpr mask_and_value<8> matcher_response{
     *        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
     *        { 'H',  'T',  'T',  'P',  '/', '1', '.', '1' }
     *    };
    */

    // common matcher for all three ssdp msg types
    //
    static constexpr mask_and_value<8> matcher{
        { 0xe8, 0x84, 0xf0, 0xe0, 0x00, 0x90, 0x00, 0x00 },
        { 0x48, 0x04, 0x50, 0x40, 0x00, 0x10, 0x00, 0x00 }
    };

};

namespace {

    [[maybe_unused]] int ssdp_fuzz_test(const uint8_t *data, size_t size) {
        datum pkt_data{data, data+size};
        perfect_hash_visitor &test_visitor = perfect_hash_visitor::get_default_perfect_hash_visitor();
        ssdp ssdp_record{pkt_data, test_visitor};
        return 0;
    }

}; // end of namespace


#endif /* SSDP_H */