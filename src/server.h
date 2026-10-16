/* SPDX-License-Identifier: MIT */
#ifndef OMNI_SERVER_H
#define OMNI_SERVER_H

#include "omnidns.h"

/*
 * Client-facing DNS server: UDP + TCP on each configured listen address.
 *
 *  - Queries are validated here (QR=0, opcode QUERY, QDCOUNT=1, class IN,
 *    EDNS version 0); everything else gets FORMERR / NOTIMP / REFUSED /
 *    BADVERS or is dropped when not even a header can be parsed.
 *  - Responses echo the client's id, RD, CD bits and question bytes (case
 *    preserved); OPT is included iff the client sent one (udp_size 1232).
 *  - UDP response size limit: 512 without EDNS, else clamp(client, 512, 1232);
 *    oversize -> cut as dns_build() cuts (AR records, else TC=1).
 *  - Answers, fresh or cached, are rendered from their wire form
 *    (dns_reply_render). Cache hits are answered synchronously while the
 *    query is read, before any per-request state exists.
 *  - TCP: RFC 7766 pipelining with out-of-order replies, bounded per
 *    connection in-flight queries, idle timeout, global connection limit.
 *  - Limits: global pending queries and per-client-address pending queries
 *    (cache hits are never pending and bypass them); UDP queries over limit
 *    are dropped, TCP ones answered REFUSED.
 */

int server_start(struct omni *o);
/* Re-bind if listen addresses/port changed. On failure, keeps old sockets. */
int server_reconfigure(struct omni *o);
void server_stop(void);

#endif
