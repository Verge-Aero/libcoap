/* libcoap unit tests
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/*
 * Subtree resources (COAP_RESOURCE_FLAGS_SUBTREE), run end to end: a server
 * and a client context in this process exchange real requests over the
 * loopback interface. Each test defends one way the paths of a subtree
 * resource could bleed into each other: request routing, observe
 * notifications, a Block2 transfer, a Block1 transfer and .well-known/core.
 */

#include "test_common.h"
#include "test_subtree.h"

#if COAP_SERVER_SUPPORT && COAP_CLIENT_SUPPORT
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <string.h>

static coap_context_t *server;
static coap_context_t *client;
static coap_session_t *session;
/* A client without libcoap's block handling: the tests drive each block */
static coap_context_t *raw_client;
static coap_session_t *raw_session;
static coap_resource_t *subtree;

/* What the client received for each one-byte request token */
#define MAX_TOKENS 24
static struct {
  coap_pdu_code_t code;
  uint8_t body[512];
  size_t len;
  int count;
  int observe;
} replies[MAX_TOKENS];

/* What the server received in a PUT, per path */
#define MAX_UPLOADS 4
static struct {
  char path[32];
  uint8_t body[512];
  size_t len;
} uploads[MAX_UPLOADS];

/* Large Block2 bodies; libcoap reads them until each transfer ends */
#define LARGE_LEN 200
static uint8_t large_body[2][LARGE_LEN];

static coap_response_t
t_response(coap_session_t *s COAP_UNUSED, const coap_pdu_t *sent COAP_UNUSED,
           const coap_pdu_t *received, const coap_mid_t mid COAP_UNUSED) {
  coap_bin_const_t token = coap_pdu_get_token(received);
  coap_opt_iterator_t opt_iter;
  size_t len, offset, total;
  const uint8_t *data;

  if (token.length != 1 || token.s[0] >= MAX_TOKENS)
    return COAP_RESPONSE_OK;
  replies[token.s[0]].code = coap_pdu_get_code(received);
  replies[token.s[0]].count++;
  replies[token.s[0]].observe =
      coap_check_option(received, COAP_OPTION_OBSERVE, &opt_iter) != NULL;
  replies[token.s[0]].len = 0;
  if (coap_get_data_large(received, &len, &data, &offset, &total) &&
      len <= sizeof(replies[0].body)) {
    memcpy(replies[token.s[0]].body, data, len);
    replies[token.s[0]].len = len;
  }
  return COAP_RESPONSE_OK;
}

/* GET on the subtree: the request's own path, or a large body for big1/big2 */
static void
t_subtree_get(coap_resource_t *resource, coap_session_t *s,
              const coap_pdu_t *request, const coap_string_t *query,
              coap_pdu_t *response) {
  coap_string_t *path = coap_get_uri_path(request);

  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  if (path && path->length == 8 && memcmp(path->s, "a/b/big", 7) == 0 &&
      (path->s[7] == '1' || path->s[7] == '2')) {
    coap_add_data_large_response(resource, s, request, response, query,
                                 COAP_MEDIATYPE_TEXT_PLAIN, -1, 0, LARGE_LEN,
                                 large_body[path->s[7] - '1'], NULL, NULL);
  } else if (path) {
    coap_add_data(response, path->length, path->s);
  }
  coap_delete_string(path);
}

/* PUT on the subtree: keep the whole body under its path */
static void
t_subtree_put(coap_resource_t *resource COAP_UNUSED,
              coap_session_t *s COAP_UNUSED, const coap_pdu_t *request,
              const coap_string_t *query COAP_UNUSED, coap_pdu_t *response) {
  coap_string_t *path = coap_get_uri_path(request);
  size_t len, offset, total, i;
  const uint8_t *data;

  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
  if (!path || path->length >= sizeof(uploads[0].path) ||
      !coap_get_data_large(request, &len, &data, &offset, &total) ||
      len > sizeof(uploads[0].body)) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
    coap_delete_string(path);
    return;
  }
  for (i = 0; i < MAX_UPLOADS; i++) {
    if (uploads[i].path[0] == '\0' ||
        strncmp(uploads[i].path, (const char *)path->s, path->length) == 0)
      break;
  }
  if (i < MAX_UPLOADS) {
    memcpy(uploads[i].path, path->s, path->length);
    uploads[i].path[path->length] = '\0';
    memcpy(uploads[i].body, data, len);
    uploads[i].len = len;
  }
  coap_delete_string(path);
}

static void
t_exact_get(coap_resource_t *resource COAP_UNUSED,
            coap_session_t *s COAP_UNUSED,
            const coap_pdu_t *request COAP_UNUSED,
            const coap_string_t *query COAP_UNUSED, coap_pdu_t *response) {
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_add_data(response, 5, (const uint8_t *)"exact");
}

/* Run both contexts until every token in want has a reply, or 2 s pass */
static void
t_pump(const int *want, size_t nwant, int count) {
  int round;
  size_t i;

  for (round = 0; round < 2000; round++) {
    int done = 1;

    coap_io_process(server, 1);
    coap_io_process(client, COAP_IO_NO_WAIT);
    coap_io_process(raw_client, COAP_IO_NO_WAIT);
    for (i = 0; i < nwant; i++) {
      if (replies[want[i]].count < count)
        done = 0;
    }
    if (done)
      return;
  }
}

/* A request for path with a one-byte token; observe -1 for none */
static coap_pdu_t *
t_request_on(coap_session_t *s, coap_pdu_code_t code, const char *path,
             uint8_t token, int observe) {
  coap_pdu_t *pdu = coap_new_pdu(COAP_MESSAGE_CON, code, s);
  uint8_t buf[4];
  const char *seg = path;

  if (!pdu)
    return NULL;
  coap_add_token(pdu, 1, &token);
  if (observe >= 0)
    coap_add_option(pdu, COAP_OPTION_OBSERVE,
                    coap_encode_var_safe(buf, sizeof(buf), observe), buf);
  while (*seg) {
    const char *end = strchr(seg, '/');
    size_t len = end ? (size_t)(end - seg) : strlen(seg);

    coap_add_option(pdu, COAP_OPTION_URI_PATH, len, (const uint8_t *)seg);
    seg += len;
    if (*seg == '/')
      seg++;
  }
  return pdu;
}

static coap_pdu_t *
t_request(coap_pdu_code_t code, const char *path, uint8_t token,
          int observe) {
  return t_request_on(session, code, path, token, observe);
}

/* One block of a Block1 or Block2 exchange on the raw session, answered */
static void
t_block(coap_pdu_code_t code, const char *path, uint8_t token,
        uint16_t option, unsigned int num, int more,
        const uint8_t *data, size_t len) {
  coap_pdu_t *pdu = t_request_on(raw_session, code, path, token, -1);
  int want = token;
  int before = replies[token].count;
  uint8_t buf[4];

  CU_ASSERT_PTR_NOT_NULL_FATAL(pdu);
  /* szx 0: 16-byte blocks */
  coap_add_option(pdu, option,
                  coap_encode_var_safe(buf, sizeof(buf),
                                       (num << 4) | (more ? 0x08 : 0)),
                  buf);
  if (data)
    coap_add_data(pdu, len, data);
  CU_ASSERT(coap_send(raw_session, pdu) != COAP_INVALID_MID);
  t_pump(&want, 1, before + 1);
  CU_ASSERT(replies[token].count == before + 1);
}

static void
t_get(const char *path, uint8_t token) {
  coap_pdu_t *pdu = t_request(COAP_REQUEST_CODE_GET, path, token, -1);

  CU_ASSERT_PTR_NOT_NULL_FATAL(pdu);
  CU_ASSERT(coap_send(session, pdu) != COAP_INVALID_MID);
}

/* A path below the subtree resource reaches it; exact resources still win */
static void
t_subtree_routing(void) {
  static const int want[] = { 1, 2, 3, 4, 5 };

  t_get("a/b/c/d", 1);     /* nearest subtree ancestor: a/b */
  t_get("a/b/x", 2);       /* registered exactly */
  t_get("a/bc", 3);        /* not below a/b: whole segments only */
  t_get("a/z", 4);         /* "a" is not a subtree resource */
  t_get("a/b", 5);         /* the subtree resource's own path */
  t_pump(want, sizeof(want) / sizeof(want[0]), 1);

  CU_ASSERT(replies[1].code == COAP_RESPONSE_CODE_CONTENT);
  CU_ASSERT(replies[1].len == 7 && memcmp(replies[1].body, "a/b/c/d", 7) == 0);
  CU_ASSERT(replies[2].len == 5 && memcmp(replies[2].body, "exact", 5) == 0);
  CU_ASSERT(replies[3].code == COAP_RESPONSE_CODE_NOT_FOUND);
  CU_ASSERT(replies[4].code == COAP_RESPONSE_CODE_NOT_FOUND);
  CU_ASSERT(replies[5].len == 3 && memcmp(replies[5].body, "a/b", 3) == 0);
}

/* .well-known/core is still served, with the subtree resource listed */
static void
t_subtree_discovery_request(void) {
  static const int want[] = { 16 };

  t_get(".well-known/core", 16);
  t_pump(want, 1, 1);
  CU_ASSERT(replies[16].code == COAP_RESPONSE_CODE_CONTENT);
  CU_ASSERT(replies[16].len > 0 &&
            memmem(replies[16].body, replies[16].len, "</a/b>", 6) != NULL);
}

/* A notification for one path reaches only that path's observers */
static void
t_subtree_observe(void) {
  static const int want[] = { 6, 7 };
  coap_pdu_t *pdu;

  pdu = t_request(COAP_REQUEST_CODE_GET, "a/b/1", 6, COAP_OBSERVE_ESTABLISH);
  CU_ASSERT_PTR_NOT_NULL_FATAL(pdu);
  CU_ASSERT(coap_send(session, pdu) != COAP_INVALID_MID);
  pdu = t_request(COAP_REQUEST_CODE_GET, "a/b/2", 7, COAP_OBSERVE_ESTABLISH);
  CU_ASSERT_PTR_NOT_NULL_FATAL(pdu);
  CU_ASSERT(coap_send(session, pdu) != COAP_INVALID_MID);
  t_pump(want, 2, 1);
  CU_ASSERT(replies[6].count == 1 && replies[6].observe);
  CU_ASSERT(replies[7].count == 1 && replies[7].observe);

  CU_ASSERT(coap_resource_notify_observers_path(subtree,
                                                coap_make_str_const("a/b/1")) == 1);
  t_pump(want, 1, 2);
  t_pump(&want[1], 1, 2);  /* give a stray notification the same chance */
  CU_ASSERT(replies[6].count == 2);
  CU_ASSERT(replies[6].len == 5 && memcmp(replies[6].body, "a/b/1", 5) == 0);
  CU_ASSERT(replies[7].count == 1);

  /* No observer for this path: nothing is triggered */
  CU_ASSERT(coap_resource_notify_observers_path(subtree,
                                                coap_make_str_const("a/b/3")) == 0);
}

/*
 * Two Block2 transfers on one session, to two paths of the subtree resource,
 * fetched block by block in turn: each block comes from its own path's body.
 */
static void
t_subtree_block2(void) {
  unsigned int num;

  for (num = 0; num * 16 < LARGE_LEN; num++) {
    size_t len = LARGE_LEN - num * 16 < 16 ? LARGE_LEN - num * 16 : 16;

    t_block(COAP_REQUEST_CODE_GET, "a/b/big1", 12, COAP_OPTION_BLOCK2, num, 0,
            NULL, 0);
    CU_ASSERT(replies[12].len == len &&
              memcmp(replies[12].body, &large_body[0][num * 16], len) == 0);
    t_block(COAP_REQUEST_CODE_GET, "a/b/big2", 13, COAP_OPTION_BLOCK2, num, 0,
            NULL, 0);
    CU_ASSERT(replies[13].len == len &&
              memcmp(replies[13].body, &large_body[1][num * 16], len) == 0);
  }
}

/*
 * Two Block1 transfers on one session, to two paths of the subtree resource,
 * sent block by block in turn: each path receives its own body whole.
 */
static void
t_subtree_block1(void) {
  static uint8_t up[2][LARGE_LEN];
  unsigned int num;
  size_t i;

  memset(up[0], 'u', LARGE_LEN);
  memset(up[1], 'v', LARGE_LEN);
  for (num = 0; num * 16 < LARGE_LEN; num++) {
    size_t len = LARGE_LEN - num * 16 < 16 ? LARGE_LEN - num * 16 : 16;
    int more = (num + 1) * 16 < LARGE_LEN;

    t_block(COAP_REQUEST_CODE_PUT, "a/b/up1", 14, COAP_OPTION_BLOCK1, num,
            more, &up[0][num * 16], len);
    t_block(COAP_REQUEST_CODE_PUT, "a/b/up2", 15, COAP_OPTION_BLOCK1, num,
            more, &up[1][num * 16], len);
  }
  CU_ASSERT(replies[14].code == COAP_RESPONSE_CODE_CHANGED);
  CU_ASSERT(replies[15].code == COAP_RESPONSE_CODE_CHANGED);
  for (i = 0; i < MAX_UPLOADS; i++) {
    if (strcmp(uploads[i].path, "a/b/up1") == 0)
      CU_ASSERT(uploads[i].len == LARGE_LEN &&
                memcmp(uploads[i].body, up[0], LARGE_LEN) == 0);
    if (strcmp(uploads[i].path, "a/b/up2") == 0)
      CU_ASSERT(uploads[i].len == LARGE_LEN &&
                memcmp(uploads[i].body, up[1], LARGE_LEN) == 0);
  }
}

/* The children a subtree resource reports, each with its own attributes */
static int
t_children(coap_resource_t *resource COAP_UNUSED, size_t index,
           coap_resource_child_t *child) {
  static const coap_link_attr_t attrs1[] = {
    { { 2, (const uint8_t *)"rt" }, { 4, (const uint8_t *)"\"t1\"" } },
    { { 3, (const uint8_t *)"obs" }, { 0, NULL } },
  };
  static const coap_link_attr_t attrs2[] = {
    { { 2, (const uint8_t *)"rt" }, { 4, (const uint8_t *)"\"t2\"" } },
  };

  switch (index) {
  case 0:
    child->uri_path = *coap_make_str_const("w/1");
    child->attrs = attrs1;
    child->num_attrs = 2;
    return 1;
  case 1:
    child->uri_path = *coap_make_str_const("w/2");
    child->attrs = attrs2;
    child->num_attrs = 1;
    return 1;
  default:
    return 0;
  }
}

static void
t_wellknown_expect(coap_context_t *ctx, const char *filter,
                   const char *expected) {
  unsigned char buf[128];
  size_t buflen = sizeof(buf);
  coap_string_t *query = NULL;
  coap_print_status_t result;

  if (filter) {
    query = coap_new_string(strlen(filter));
    CU_ASSERT_PTR_NOT_NULL_FATAL(query);
    memcpy(query->s, filter, strlen(filter));
  }
  result = coap_print_wellknown(ctx, buf, &buflen, 0, query);
  coap_delete_string(query);
  CU_ASSERT((result & COAP_PRINT_STATUS_ERROR) == 0);
  CU_ASSERT(COAP_PRINT_OUTPUT_LENGTH(result) == strlen(expected));
  CU_ASSERT(memcmp(buf, expected, strlen(expected)) == 0);
}

/* .well-known/core lists a subtree's children and filters them like resources */
static void
t_subtree_wellknown(void) {
  coap_context_t *ctx = coap_new_context(NULL);
  coap_resource_t *r;

  CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);
  r = coap_resource_init(coap_make_str_const("w"),
                         COAP_RESOURCE_FLAGS_SUBTREE |
                         COAP_RESOURCE_HIDE_WELLKNOWN_CORE);
  CU_ASSERT_PTR_NOT_NULL_FATAL(r);
  coap_resource_set_child_handler(r, t_children);
  coap_add_resource(ctx, r);

  t_wellknown_expect(ctx, NULL, "</w/1>;rt=\"t1\";obs,</w/2>;rt=\"t2\"");
  t_wellknown_expect(ctx, "rt=t2", "</w/2>;rt=\"t2\"");
  t_wellknown_expect(ctx, "href=/w/1", "</w/1>;rt=\"t1\";obs");
  t_wellknown_expect(ctx, "href=w*", "</w/1>;rt=\"t1\";obs,</w/2>;rt=\"t2\"");

  /* Without HIDE_WELLKNOWN_CORE the subtree resource is listed too */
  r->flags &= ~COAP_RESOURCE_HIDE_WELLKNOWN_CORE;
  t_wellknown_expect(ctx, NULL,
                     "</w>,</w/1>;rt=\"t1\";obs,</w/2>;rt=\"t2\"");
  coap_free_context(ctx);
}

static int
t_subtree_tests_create(void) {
  coap_address_t addr;
  coap_endpoint_t *ep;
  coap_resource_t *r;
  size_t i;

  for (i = 0; i < LARGE_LEN; i++) {
    large_body[0][i] = (uint8_t)('A' + i % 26);
    large_body[1][i] = (uint8_t)('a' + i % 26);
  }

  coap_address_init(&addr);
  addr.size = sizeof(struct sockaddr_in6);
  addr.addr.sin6.sin6_family = AF_INET6;
  addr.addr.sin6.sin6_addr = in6addr_loopback;
  addr.addr.sin6.sin6_port = 0;

  server = coap_new_context(NULL);
  client = coap_new_context(NULL);
  if (!server || !client)
    return 1;
  /* Small blocks, so each large body spans many exchanges */
  coap_context_set_block_mode(server, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
  coap_context_set_block_mode(client, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
  coap_context_set_max_block_size(server, 16);
  coap_context_set_max_block_size(client, 16);
  ep = coap_new_endpoint(server, &addr, COAP_PROTO_UDP);
  if (!ep)
    return 1;

  subtree = coap_resource_init(coap_make_str_const("a/b"),
                               COAP_RESOURCE_FLAGS_SUBTREE);
  coap_register_request_handler(subtree, COAP_REQUEST_GET, t_subtree_get);
  coap_register_request_handler(subtree, COAP_REQUEST_PUT, t_subtree_put);
  coap_resource_set_get_observable(subtree, 1);
  coap_add_resource(server, subtree);

  r = coap_resource_init(coap_make_str_const("a/b/x"), 0);
  coap_register_request_handler(r, COAP_REQUEST_GET, t_exact_get);
  coap_add_resource(server, r);

  r = coap_resource_init(coap_make_str_const("a"), 0);
  coap_register_request_handler(r, COAP_REQUEST_GET, t_exact_get);
  coap_add_resource(server, r);

  coap_register_response_handler(client, t_response);
  session = coap_new_client_session(client, NULL, &ep->bind_addr,
                                    COAP_PROTO_UDP);
  raw_client = coap_new_context(NULL);
  if (!raw_client)
    return 1;
  coap_register_response_handler(raw_client, t_response);
  raw_session = coap_new_client_session(raw_client, NULL, &ep->bind_addr,
                                        COAP_PROTO_UDP);
  return session == NULL || raw_session == NULL;
}

static int
t_subtree_tests_remove(void) {
  coap_session_release(session);
  coap_session_release(raw_session);
  coap_free_context(client);
  coap_free_context(raw_client);
  coap_free_context(server);
  return 0;
}

CU_pSuite
t_init_subtree_tests(void) {
  CU_pSuite suite;

  suite = CU_add_suite("subtree resources", t_subtree_tests_create,
                       t_subtree_tests_remove);
  if (!suite) {                        /* signal error */
    fprintf(stderr, "W: cannot add subtree resource test suite (%s)\n",
            CU_get_error_msg());

    return NULL;
  }

#define SUBTREE_TEST(s,t)                                                \
  if (!CU_ADD_TEST(s,t)) {                                              \
    fprintf(stderr, "W: cannot add subtree resource test (%s)\n",       \
            CU_get_error_msg());                                        \
  }

  SUBTREE_TEST(suite, t_subtree_routing);
  SUBTREE_TEST(suite, t_subtree_discovery_request);
  SUBTREE_TEST(suite, t_subtree_observe);
  SUBTREE_TEST(suite, t_subtree_block2);
  SUBTREE_TEST(suite, t_subtree_block1);
  SUBTREE_TEST(suite, t_subtree_wellknown);

  return suite;
}

#else /* ! COAP_SERVER_SUPPORT || ! COAP_CLIENT_SUPPORT */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* ! COAP_SERVER_SUPPORT || ! COAP_CLIENT_SUPPORT */
