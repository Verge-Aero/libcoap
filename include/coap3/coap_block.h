/*
 * coap_block.h -- block transfer
 *
 * Copyright (C) 2010-2012,2014-2015 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2022-2025           Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_block.h
 * @brief CoAP Block information
 */

#ifndef COAP_BLOCK_H_
#define COAP_BLOCK_H_

#include "coap_encode.h"
#include "coap_option.h"
#include "coap_pdu.h"

/**
 * @ingroup application_api
 * @defgroup block Block Transfer
 * API for handling PDUs using CoAP Block options (RFC7959)
 * @{
 */

#ifndef COAP_MAX_BLOCK_SZX
/**
 * The largest value for the SZX component in a Block option.
 */
#define COAP_MAX_BLOCK_SZX      6
#endif /* COAP_MAX_BLOCK_SZX */

/**
 * Structure of Block options.
 */
typedef struct {
  unsigned int num;       /**< block number */
  unsigned int m:1;       /**< 1 if more blocks follow, 0 otherwise */
  unsigned int szx:3;     /**< block size */
} coap_block_t;

/**
 * Structure of Block options with BERT support.
 */
typedef struct {
  unsigned int num;       /**< block number */
  unsigned int m:1;       /**< 1 if more blocks follow, 0 otherwise */
  unsigned int szx:3;     /**< block size (0-6) */
  unsigned int aszx:3;    /**< block size (0-7 including BERT */
  unsigned int defined:1; /**< Set if block found */
  unsigned int bert:1;    /**< Operating as BERT */
  uint32_t chunk_size;    /**< > 1024 if BERT */
} coap_block_b_t;

#define COAP_BLOCK_USE_LIBCOAP  0x01 /* Use libcoap to do block requests */
#define COAP_BLOCK_SINGLE_BODY  0x02 /* Deliver the data as a single body */
#define COAP_BLOCK_TRY_Q_BLOCK   0x04 /* Try Q-Block method */
#define COAP_BLOCK_USE_M_Q_BLOCK 0x08 /* Use M bit when recovering Q-Block2 */
#define COAP_BLOCK_NO_PREEMPTIVE_RTAG 0x10 /* (cl) Don't use pre-emptive Request-Tags */
#define COAP_BLOCK_STLESS_FETCH  0x20 /* (cl) Assume server supports stateless FETCH */
#define COAP_BLOCK_STLESS_BLOCK2 0x40 /* (svr)Server is stateless for handling Block2 */
#define COAP_BLOCK_NOT_RANDOM_BLOCK1 0x80 /* (svr)Disable server handling random order
                                             block1 */
#define COAP_BLOCK_STREAM_BODY  0x100 /* (svr)Stream each received block to the app as it
                                         arrives (out of order possible) rather than buffering
                                         the whole body. The app must supply a seekable,
                                         random-offset sink and use
                                         coap_get_block_body_complete() to detect when the full
                                         body has arrived. Bounds receive RAM to one block plus
                                         the missing-block bitmap. */
/* WARNING: Added defined values must not encroach into 0xff000000 which are defined elsewhere */

/**
 * Returns the value of the least significant byte of a Block option @p opt.
 * For zero-length options (i.e. num == m == szx == 0), COAP_OPT_BLOCK_LAST
 * returns @c NULL.
 */
#define COAP_OPT_BLOCK_LAST(opt) \
  (coap_opt_length(opt) ? (coap_opt_value(opt) + (coap_opt_length(opt)-1)) : 0)

/** Returns the value of the last byte of @p opt. */
#define COAP_OPT_BLOCK_END_BYTE(opt) \
  ((coap_opt_length(opt) && coap_opt_value(opt)) ? \
   *(coap_opt_value(opt) + (coap_opt_length(opt)-1)) : 0)

/** Returns the value of the More-bit of a Block option @p opt. */
#define COAP_OPT_BLOCK_MORE(opt) \
  (coap_opt_length(opt) ? (COAP_OPT_BLOCK_END_BYTE(opt) & 0x08) : 0)

/** Returns the value of the SZX-field of a Block option @p opt. */
#define COAP_OPT_BLOCK_SZX(opt)  \
  (coap_opt_length(opt) ? (COAP_OPT_BLOCK_END_BYTE(opt) & 0x07) : 0)

/**
 * Returns the value of field @c num in the given block option @p block_opt.
 */
unsigned int coap_opt_block_num(const coap_opt_t *block_opt);

/**
 * Checks if more than @p num blocks are required to deliver @p data_len
 * bytes of data for a block size of 1 << (@p szx + 4).
 */
COAP_STATIC_INLINE int
coap_more_blocks(size_t data_len, unsigned int num, uint16_t szx) {
  return ((num+1) << (szx + 4)) < data_len;
}

#if 0
/** Sets the More-bit in @p block_opt */
COAP_STATIC_INLINE void
coap_opt_block_set_m(coap_opt_t *block_opt, int m) {
  if (m)
    *(coap_opt_value(block_opt) + (coap_opt_length(block_opt) - 1)) |= 0x08;
  else
    *(coap_opt_value(block_opt) + (coap_opt_length(block_opt) - 1)) &= ~0x08;
}
#endif

/**
 * Initializes @p block from @p pdu. @p number must be either COAP_OPTION_BLOCK1
 * or COAP_OPTION_BLOCK2. When option @p number was found in @p pdu, @p block is
 * initialized with values from this option and the function returns the value
 * @c 1. Otherwise, @c 0 is returned.
 *
 * @param pdu    The pdu to search for option @p number.
 * @param number The option number to search for (must be COAP_OPTION_BLOCK1 or
 *               COAP_OPTION_BLOCK2).
 * @param block  The block structure to initialize.
 *
 * @return       @c 1 on success, @c 0 otherwise.
 */
int coap_get_block(const coap_pdu_t *pdu, coap_option_num_t number,
                   coap_block_t *block);


/**
 * Initializes @p block from @p pdu. @p number must be either COAP_OPTION_BLOCK1
 * or COAP_OPTION_BLOCK2. When option @p number was found in @p pdu, @p block is
 * initialized with values from this option and the function returns the value
 * @c 1. Otherwise, @c 0 is returned. BERT information is abstracted as
 * appropriate.
 *
 * @param session THe session that the pdu is associated with,
 * @param pdu    The pdu to search for option @p number.
 * @param number The option number to search for (must be COAP_OPTION_BLOCK1 or
 *               COAP_OPTION_BLOCK2).
 * @param block  The block structure to initialize.
 *
 * @return       @c 1 on success, @c 0 otherwise.
 */
int coap_get_block_b(const coap_session_t *session, const coap_pdu_t *pdu,
                     coap_option_num_t number, coap_block_b_t *block);

/**
 * Writes a block option of type @p number to message @p pdu. If the requested
 * block size is too large to fit in @p pdu, it is reduced accordingly. An
 * exception is made for the final block when less space is required. The actual
 * length of the resource is specified in @p data_length.
 *
 * This function may change *block to reflect the values written to @p pdu. As
 * the function takes into consideration the remaining space @p pdu, no more
 * options should be added after coap_write_block_opt() has returned.
 *
 * @param block       The block structure to use. On return, this object is
 *                    updated according to the values that have been written to
 *                    @p pdu.
 * @param number      COAP_OPTION_BLOCK1 or COAP_OPTION_BLOCK2.
 * @param pdu         The message where the block option should be written.
 * @param data_length The length of the actual data that will be added the @p
 *                    pdu by calling coap_add_block().
 *
 * @return            @c 1 on success, or a negative value on error.
 */
int coap_write_block_opt(coap_block_t *block,
                         coap_option_num_t number,
                         coap_pdu_t *pdu,
                         size_t data_length);
/**
 * Writes a block option of type @p number to message @p pdu. If the requested
 * block size is too large to fit in @p pdu, it is reduced accordingly. An
 * exception is made for the final block when less space is required. The actual
 * length of the resource is specified in @p data_length.
 *
 * This function may change *block to reflect the values written to @p pdu. As
 * the function takes into consideration the remaining space @p pdu, no more
 * options should be added after coap_write_block_opt() has returned.
 *
 * @param session     The CoAP session.
 * @param block       The block structure to use. On return, this object is
 *                    updated according to the values that have been written to
 *                    @p pdu.
 * @param number      COAP_OPTION_BLOCK1 or COAP_OPTION_BLOCK2.
 * @param pdu         The message where the block option should be written.
 * @param data_length The length of the actual data that will be added the @p
 *                    pdu by calling coap_add_block().
 *
 * @return            @c 1 on success, or a negative value on error.
 */
int coap_write_block_b_opt(coap_session_t *session,
                           coap_block_b_t *block,
                           coap_option_num_t number,
                           coap_pdu_t *pdu,
                           size_t data_length);


/**
 * Adds the @p block_num block of size 1 << (@p block_szx + 4) from source @p
 * data to @p pdu.
 *
 * @param pdu       The message to add the block.
 * @param len       The length of @p data.
 * @param data      The source data to fill the block with.
 * @param block_num The actual block number.
 * @param block_szx Encoded size of block @p block_number.
 *
 * @return          @c 1 on success, @c 0 otherwise.
 */
int coap_add_block(coap_pdu_t *pdu,
                   size_t len,
                   const uint8_t *data,
                   unsigned int block_num,
                   unsigned char block_szx);

/**
 * Adds the appropriate payload data of the body to the @p pdu.
 *
 * @param pdu       The message to add the block.
 * @param len       The length of @p data.
 * @param data      The source data to fill the block with.
 * @param block     The block information (including potentially BERT)
 *
 * @return          @c 1 on success, @c 0 otherwise.
 */
int coap_add_block_b_data(coap_pdu_t *pdu, size_t len, const uint8_t *data,
                          coap_block_b_t *block);

/**
 * Re-assemble payloads into a body
 *
 * @param body_data The pointer to the data for the body holding the
 *                  representation so far or NULL if the first time.
 * @param length    The length of @p data.
 * @param data      The payload data to update the body with.
 * @param offset    The offset of the @p data into the body.
 * @param total     The estimated total size of the body.
 *
 * @return          The current representation of the body or @c NULL if error.
 *                  If NULL, @p body_data will have been de-allocated.
 */
COAP_API coap_binary_t *coap_block_build_body(coap_binary_t *body_data, size_t length,
                                              const uint8_t *data, size_t offset, size_t total);

/**
 * Adds the appropriate part of @p data to the @p response pdu.  If blocks are
 * required, then the appropriate block will be added to the PDU and sent.
 * Adds a ETag option that is the hash of the entire data if the data is to be
 * split into blocks
 * Used by a request handler.
 *
 * Note: The application will get called for every packet of a large body to
 * process. Consider using coap_add_data_response_large() instead.
 *
 * @param request    The requesting pdu.
 * @param response   The response pdu.
 * @param media_type The format of the data.
 * @param maxage     The maxmimum life of the data. If @c -1, then there
 *                   is no maxage.
 * @param length     The total length of the data.
 * @param data       The entire data block to transmit.
 *
 */
void coap_add_data_blocked_response(const coap_pdu_t *request,
                                    coap_pdu_t *response,
                                    uint16_t media_type,
                                    int maxage,
                                    size_t length,
                                    const uint8_t *data);

/**
 * Callback handler for de-allocating the data based on @p app_ptr provided to
 * coap_add_data_large_*() functions following transmission of the supplied
 * data.
 *
 * @param session The session that this data is associated with
 * @param app_ptr The application provided pointer provided to the
 *                coap_add_data_large_* functions.
 */
typedef void (*coap_release_large_data_t)(coap_session_t *session,
                                          void *app_ptr);

/**
 * Callback to write one received block of a large request body straight to the
 * application's sink, used with COAP_BLOCK_STREAM_BODY / coap_resource_set_block_stream().
 *
 * Blocks may arrive out of order, so the sink must be random-offset addressable.
 * No response is generated per block (Q-Block bursts are unacknowledged); the
 * library's missing-block recovery is unaffected. The resource's normal request
 * handler is still invoked once, after the whole body has arrived, with a NULL
 * body and coap_get_block_body_complete() == 1, so the application can emit its
 * response and release the sink.
 *
 * @param session  The session the body is arriving on.
 * @param app_ptr  The pointer returned by the coap_block_body_open_t callback.
 * @param offset   Byte offset of this block within the full body.
 * @param data     This block's bytes.
 * @param length   This block's length.
 */
typedef void (*coap_block_body_write_t)(coap_session_t *session, void *app_ptr,
                                        size_t offset, const uint8_t *data,
                                        size_t length);

/**
 * Callback invoked once, when the first block of a large request body arrives on
 * a resource that has opted into streaming receive via coap_resource_set_block_stream().
 *
 * The application opens a sink for the body and returns an opaque pointer for it,
 * setting @p out_write_fn to the per-block writer. Returning NULL declines streaming
 * for this body and falls back to whole-body buffering.
 *
 * @param session       The session the body is arriving on.
 * @param resource      The resource receiving the body.
 * @param request       The first request PDU (for inspecting Uri-Path / Uri-Query etc).
 * @param total_length  Full body size from the Size1 option, or 0 if not provided.
 * @param out_write_fn  Set to the per-block write callback.
 *
 * @return Opaque application pointer passed to the write callback, or NULL to decline.
 */
typedef void *(*coap_block_body_open_t)(coap_session_t *session,
                                        coap_resource_t *resource,
                                        const coap_pdu_t *request,
                                        size_t total_length,
                                        coap_block_body_write_t *out_write_fn);

/**
 * Opt @p resource into streaming receive of large request bodies. When set (and the
 * session block_mode does not force a single body), each received block is written
 * to the application's sink as it arrives instead of the whole body being buffered,
 * bounding receive memory to one block plus the missing-block bitmap. Pass NULL to
 * disable.
 *
 * @param resource The resource.
 * @param open_fn  The body-open callback, or NULL to disable streaming receive.
 */
void coap_resource_set_block_stream(coap_resource_t *resource,
                                    coap_block_body_open_t open_fn);

/**
 * Query whether this delivery of a (streamed) large body is the completion call —
 * i.e. the full body has now arrived. Valid inside a resource request handler when
 * the resource uses coap_resource_set_block_stream(). On the completion call the PDU
 * carries a NULL body (all blocks were already streamed to the sink).
 *
 * @param pdu The request PDU passed to the handler.
 *
 * @return 1 if the full body has arrived (completion call), else 0.
 */
int coap_get_block_body_complete(const coap_pdu_t *pdu);

/**
 * Associates given data with the @p pdu that is passed as second parameter.
 *
 * This function will fail if data has already been added to the @p pdu.
 *
 * If all the data can be transmitted in a single PDU, this is functionally
 * the same as coap_add_data() except @p release_func (if not NULL) will get
 * invoked after data transmission.
 *
 * Used for a client request.
 *
 * If the data spans multiple PDUs, then the data will get transmitted using
 * (Q-)Block1 option with the addition of the Size1 and Request-Tag options.
 * The underlying library will handle the transmission of the individual blocks.
 * Once the body of data has been transmitted (or a failure occurred), then
 * @p release_func (if not NULL) will get called so the application can
 * de-allocate the @p data based on @p app_data. It is the responsibility of
 * the application not to change the contents of @p data until the data
 * transfer has completed.
 *
 * There is no need for the application to include the (Q-)Block1 option in the
 * @p pdu.
 *
 * coap_add_data_large_request() (or the alternative coap_add_data_large_*()
 * functions) must be called only once per PDU and must be the last PDU update
 * before the PDU is transmitted. The (potentially) initial data will get
 * transmitted when coap_send() is invoked.
 *
 * Note: COAP_BLOCK_USE_LIBCOAP must be set by coap_context_set_block_mode()
 * for libcoap to work correctly when using this function.
 *
 * @param session  The session to associate the data with.
 * @param pdu      The PDU to associate the data with.
 * @param length   The length of data to transmit.
 * @param data     The data to transmit.
 * @param release_func The function to call to de-allocate @p data or @c NULL
 *                 if the function is not required.
 * @param app_ptr  A Pointer that the application can provide for when
 *                 release_func() is called.
 *
 * @return @c 1 if addition is successful, else @c 0.
 */
COAP_API int coap_add_data_large_request(coap_session_t *session,
                                         coap_pdu_t *pdu,
                                         size_t length,
                                         const uint8_t *data,
                                         coap_release_large_data_t release_func,
                                         void *app_ptr);

/**
 * Associates given data with the @p response pdu that is passed as fourth
 * parameter.
 *
 * This function will fail if data has already been added to the @p pdu.
 *
 * If all the data can be transmitted in a single PDU, this is functionally
 * the same as coap_add_data() except @p release_func (if not NULL) will get
 * invoked after data transmission. The Content-Format, Max-Age and ETag
 * options may be added in as appropriate.
 *
 * Used by a server request handler to create the response.
 *
 * If the data spans multiple PDUs, then the data will get transmitted using
 * (Q-)Block2 (response) option with the addition of the Size2 and ETag
 * options. The underlying library will handle the transmission of the
 * individual blocks. Once the body of data has been transmitted (or a
 * failure occurred), then @p release_func (if not NULL) will get called so the
 * application can de-allocate the @p data based on @p app_data. It is the
 * responsibility of the application not to change the contents of @p data
 * until the data transfer has completed.
 *
 * There is no need for the application to include the (Q-)Block2 option in the
 * @p pdu.
 *
 * coap_add_data_large_response() (or the alternative coap_add_data_large_*()
 * functions) must be called only once per PDU and must be the last PDU update
 * before returning from the request handler function.
 *
 * Note: COAP_BLOCK_USE_LIBCOAP must be set by coap_context_set_block_mode()
 * for libcoap to work correctly when using this function.
 *
 * @param resource   The resource the data is associated with.
 * @param session    The coap session.
 * @param request    The requesting pdu.
 * @param response   The response pdu.
 * @param query      The query taken from the (original) requesting pdu.
 * @param media_type The content format of the data.
 * @param maxage     The maxmimum life of the data. If @c -1, then there
 *                   is no maxage.
 * @param etag       ETag to use if not 0.
 * @param length     The total length of the data.
 * @param data       The entire data block to transmit.
 * @param release_func The function to call to de-allocate @p data or NULL if
 *                   the function is not required.
 * @param app_ptr    A Pointer that the application can provide for when
 *                   release_func() is called.
 *
 * @return @c 1 if addition is successful, else @c 0.
 */
COAP_API int coap_add_data_large_response(coap_resource_t *resource,
                                          coap_session_t *session,
                                          const coap_pdu_t *request,
                                          coap_pdu_t *response,
                                          const coap_string_t *query,
                                          uint16_t media_type,
                                          int maxage,
                                          uint64_t etag,
                                          size_t length,
                                          const uint8_t *data,
                                          coap_release_large_data_t release_func,
                                          void *app_ptr);

/**
 * Callback to read @p length bytes of a large body at @p offset into @p buf, used by the streaming
 * coap_add_data_large_*_stream() variants. The library calls this on demand for each block it sends
 * (including retransmits and Q-Block missing-block recovery, which may re-read earlier offsets), so
 * the source must be random-offset readable. This lets a constrained device send a body larger than
 * its RAM straight from storage — only one block is held in memory at a time.
 *
 * @param session The session the body is being sent on.
 * @param app_ptr The application pointer passed to coap_add_data_large_*_stream().
 * @param offset  Byte offset of the requested block within the full body.
 * @param length  Number of bytes to read.
 * @param buf     Buffer of at least @p length bytes to read into.
 *
 * @return Number of bytes read into @p buf (should equal @p length for an in-range block).
 */
typedef size_t (*coap_get_block_data_t)(coap_session_t *session, void *app_ptr,
                                        size_t offset, size_t length, uint8_t *buf);

/**
 * Streaming variant of coap_add_data_large_request(): the body of @p total_length bytes is read on
 * demand via @p read_func instead of being supplied up front, so only one block is held in RAM.
 * Otherwise identical to coap_add_data_large_request(). @p release_func (if not NULL) is called when
 * the transfer completes or fails.
 *
 * @param session       The session to associate the data with.
 * @param pdu           The PDU to associate the data with.
 * @param total_length  The total length of the body.
 * @param read_func     Callback to read each block of the body on demand.
 * @param release_func  Called when the body has been transmitted or failed, or NULL.
 * @param app_ptr       Application pointer passed to @p read_func and @p release_func.
 *
 * @return @c 1 if addition is successful, else @c 0.
 */
COAP_API int coap_add_data_large_request_stream(coap_session_t *session,
                                                coap_pdu_t *pdu,
                                                size_t total_length,
                                                coap_get_block_data_t read_func,
                                                coap_release_large_data_t release_func,
                                                void *app_ptr);

/**
 * Streaming variant of coap_add_data_large_response(): the body of @p total_length bytes is read on
 * demand via @p read_func instead of being supplied up front, so only one block is held in RAM. This
 * lets a server serve a body larger than its RAM from storage, with Q-Block2 burst. Otherwise
 * identical to coap_add_data_large_response(). @p release_func (if not NULL) is called when the
 * transfer completes or fails.
 *
 * @param resource      The resource the data is associated with.
 * @param session       The coap session.
 * @param request       The requesting pdu.
 * @param response      The response pdu.
 * @param query         The query taken from the (original) requesting pdu.
 * @param media_type    The content format of the data.
 * @param maxage        The maximum life of the data, or -1 for none.
 * @param etag          ETag to use if not 0.
 * @param total_length  The total length of the body.
 * @param read_func     Callback to read each block of the body on demand.
 * @param release_func  Called when the body has been transmitted or failed, or NULL.
 * @param app_ptr       Application pointer passed to @p read_func and @p release_func.
 *
 * @return @c 1 if addition is successful, else @c 0.
 */
COAP_API int coap_add_data_large_response_stream(coap_resource_t *resource,
                                                 coap_session_t *session,
                                                 const coap_pdu_t *request,
                                                 coap_pdu_t *response,
                                                 const coap_string_t *query,
                                                 uint16_t media_type,
                                                 int maxage,
                                                 uint64_t etag,
                                                 size_t total_length,
                                                 coap_get_block_data_t read_func,
                                                 coap_release_large_data_t release_func,
                                                 void *app_ptr);

/**
 * Set the context level CoAP block handling bits for handling RFC7959.
 * These bits flow down to a session when a session is created and if the peer
 * does not support something, an appropriate bit may get disabled in the
 * session block_mode.
 * The session block_mode then flows down into coap_crcv_t or coap_srcv_t where
 * again an appropriate bit may get disabled.
 *
 * Note: This function must be called before the session is set up.
 *
 * Note: COAP_BLOCK_USE_LIBCOAP must be set if libcoap is to do all the
 * block tracking and requesting, otherwise the application will have to do
 * all of this work (the default if coap_context_set_block_mode() is not
 * called).
 *
 * @param context        The coap_context_t object.
 * @param block_mode     Zero or more COAP_BLOCK_ or'd options
 */
COAP_API void coap_context_set_block_mode(coap_context_t *context,
                                          uint32_t block_mode);

/**
 * Set the context level maximum block size that the server supports when sending
 * or receiving packets with Block1 or Block2 options.
 * This maximum block size flows down to a session when a session is created.
 *
 * Note: This function must be called before the session is set up.
 *
 * Note: COAP_BLOCK_USE_LIBCOAP must be set using coap_context_set_block_mode()
 * if libcoap is to do this work.
 *
 * @param context        The coap_context_t object.
 * @param max_block_size The maximum block size a server supports.  Can be 0
 *                       (reset), or must be 16, 32, 64, 128, 256, 512 or 1024.
 */
COAP_API int coap_context_set_max_block_size(coap_context_t *context, size_t max_block_size);

/**@}*/

#endif /* COAP_BLOCK_H_ */
