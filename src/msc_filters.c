
#include "msc_filters.h"
#include "msc_utils.h"


/*
 * Pulls the whole request body off the network, hands every chunk to
 * libmodsecurity, and parks the buckets in msr->body_replay_bb so that
 * MODSECURITY_IN can replay them to whoever reads the body next (the
 * content handler, mod_proxy, ...). Called from the fixups phase, before
 * any request-level input filter exists, so it reads straight from
 * r->input_filters: HTTP_IN takes care of Content-Length, chunked
 * transfer-coding, "Expect: 100-continue" and LimitRequestBody for us.
 *
 * Reading stops early once libmodsecurity refuses more data
 * (SecRequestBodyLimit reached): with SecRequestBodyLimitAction Reject
 * an intervention is already pending, with ProcessPartial the rules run
 * on what was read and the rest of the body stays on the network, where
 * the replay filter falls through to it once the buffered part is gone.
 * Either way the buffered copy is bounded by that limit.
 *
 * Returns OK, or the HTTP status to answer the request with.
 */
int msc_read_request_body(msc_t *msr)
{
    request_rec *r = msr->r;
    apr_bucket_brigade *bb;
    apr_status_t rv;
    int seen_eos = 0;
    int limit_hit = 0;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    while (!seen_eos && !limit_hit)
    {
        apr_bucket *b;

        rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                APR_BLOCK_READ, HUGE_STRING_LEN);
        if (rv != APR_SUCCESS)
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                    "ModSecurity: Error reading request body");
            apr_brigade_destroy(bb);
            return ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
        }

        for (b = APR_BRIGADE_FIRST(bb);
             b != APR_BRIGADE_SENTINEL(bb);
             b = APR_BUCKET_NEXT(b))
        {
            const char *data;
            apr_size_t len;

            if (APR_BUCKET_IS_EOS(b))
            {
                seen_eos = 1;
                break;
            }
            if (APR_BUCKET_IS_METADATA(b))
            {
                continue;
            }

            rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS)
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                        "ModSecurity: Error reading request body bucket");
                apr_brigade_destroy(bb);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            /* The bucket may point at a transient buffer owned by the
             * filter below us; make sure it survives until replay. */
            rv = apr_bucket_setaside(b, r->pool);
            if (rv != APR_SUCCESS)
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                        "ModSecurity: Error setting aside request body bucket");
                apr_brigade_destroy(bb);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            if (len > 0 && msc_append_request_body(msr->t,
                        (const unsigned char *)data, len) != 1)
            {
                limit_hit = 1;
                break;
            }
        }

        /* Everything that came off the network goes into the replay
         * brigade untouched, including the EOS. */
        APR_BRIGADE_CONCAT(msr->body_replay_bb, bb);
    }

    apr_brigade_destroy(bb);
    return OK;
}


/*
 * Request input filter. hook_request_late already drained the body from
 * the network so ModSecurity could inspect it before the real content
 * handler runs. Replay the buffered copy here instead of reading the (now
 * empty) network stream again, so the content handler still sees the
 * body. Once fully replayed, remove ourselves so later reads (or a body
 * left unread by the handler, drained via ap_discard_request_body) fall
 * straight through to the filter below, which is already at EOS.
 */
apr_status_t input_filter(ap_filter_t *f, apr_bucket_brigade *pbbOut,
        ap_input_mode_t mode, apr_read_type_e block, apr_off_t nbytes)
{
    msc_t *msr = (msc_t *)f->ctx;
    apr_bucket_brigade *replay;
    apr_bucket *stop;
    apr_status_t rv;

    /* Do we have the context? */
    if (msr == NULL)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                "ModSecurity: Internal Error: msr is null in input filter.");
        ap_remove_input_filter(f);
        return APR_EGENERAL;
    }

    replay = msr->body_replay_bb;

    /* Nothing left to replay -- either this filter already replayed the
     * whole body, or (subrequests/internal redirects share the same msr
     * as the main request via retrieve_tx_context, while hook_insert_filter
     * adds a fresh MODSECURITY_IN instance per request) another instance
     * got there first. Either way, step out of the way: an input filter
     * must not return success with an empty brigade. */
    if (APR_BRIGADE_EMPTY(replay))
    {
        ap_remove_input_filter(f);
        return ap_get_brigade(f->next, pbbOut, mode, block, nbytes);
    }

    switch (mode)
    {
    case AP_MODE_GETLINE:
        rv = apr_brigade_split_line(pbbOut, replay, block, HUGE_STRING_LEN);
        break;

    case AP_MODE_READBYTES:
    case AP_MODE_SPECULATIVE:
        /* Hand out at most nbytes, splitting at a bucket boundary, so
         * callers that relay the body onward in fixed-size chunks (e.g.
         * mod_proxy) don't get more than they asked for in one call. */
        if (nbytes > 0)
        {
            rv = apr_brigade_partition(replay, nbytes, &stop);
            if (rv != APR_SUCCESS && rv != APR_INCOMPLETE)
            {
                return rv;
            }
        }
        else
        {
            stop = APR_BRIGADE_SENTINEL(replay);
        }

        rv = APR_SUCCESS;
        if (mode == AP_MODE_SPECULATIVE)
        {
            /* A peek: the reader expects the same data again on its
             * next real read, so hand out copies and keep ours. */
            apr_bucket *b;
            for (b = APR_BRIGADE_FIRST(replay); b != stop;
                 b = APR_BUCKET_NEXT(b))
            {
                apr_bucket *copy;
                rv = apr_bucket_copy(b, &copy);
                if (rv != APR_SUCCESS)
                {
                    return rv;
                }
                APR_BRIGADE_INSERT_TAIL(pbbOut, copy);
            }
            return APR_SUCCESS;
        }

        while (!APR_BRIGADE_EMPTY(replay) && APR_BRIGADE_FIRST(replay) != stop)
        {
            apr_bucket *b = APR_BRIGADE_FIRST(replay);
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(pbbOut, b);
        }
        break;

    case AP_MODE_EXHAUSTIVE:
        APR_BRIGADE_CONCAT(pbbOut, replay);
        rv = APR_SUCCESS;
        break;

    default:
        /* AP_MODE_EATCRLF and AP_MODE_INIT are not body reads. */
        return ap_get_brigade(f->next, pbbOut, mode, block, nbytes);
    }

    if (rv == APR_SUCCESS && APR_BRIGADE_EMPTY(replay))
    {
        ap_remove_input_filter(f);
    }
    return rv;
}


apr_status_t output_filter(ap_filter_t *f, apr_bucket_brigade *bb_in)
{
    request_rec *r = f->r;
    msc_t *msr = (msc_t *)f->ctx;

    /* Do we have the context? */
    if (msr == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, f->r->server,
                "ModSecurity: Internal Error: msr is null in output filter.");
        ap_remove_output_filter(f);
        return send_error_bucket(msr, f, HTTP_INTERNAL_SERVER_ERROR);
    }

    /* response headers */
    {
        const apr_array_header_t *arr = NULL;
        const apr_table_entry_t *te = NULL;
        int i, it;

        arr = apr_table_elts(r->err_headers_out);
        te = (apr_table_entry_t *)arr->elts;
        for (i = 0; i < arr->nelts; i++)
        {
            const char *key = te[i].key;
            const char *val = te[i].val;
            msc_add_response_header(msr->t, key, val);
        }

        arr = apr_table_elts(r->headers_out);
        te = (apr_table_entry_t *)arr->elts;
        for (i = 0; i < arr->nelts; i++)
        {
            const char *key = te[i].key;
            const char *val = te[i].val;
            msc_add_response_header(msr->t, key, val);
        }

        msc_process_response_headers(msr->t, r->status, "HTTP 1.1");

        it = process_intervention(msr->t, r);
        if (it != N_INTERVENTION_STATUS)
        {
            ap_remove_output_filter(f);
            return send_error_bucket(msr, f, it);
        }
    }

    /* response body */
    {
        apr_bucket *pbktIn;
        int it;

        for (pbktIn = APR_BRIGADE_FIRST(bb_in);
            pbktIn != APR_BRIGADE_SENTINEL(bb_in);
            pbktIn = APR_BUCKET_NEXT(pbktIn))
        {
            const char *data;
            apr_size_t len;
            apr_status_t rv;

            rv = apr_bucket_read(pbktIn, &data, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, f->r->server,
                    "ModSecurity: Error reading response body bucket");
                return rv;
            }

            msc_append_response_body(msr->t, data, len);
        }
        msc_process_response_body(msr->t);

        it = process_intervention(msr->t, r);
        if (it != N_INTERVENTION_STATUS)
        {
            ap_remove_output_filter(f);
            return send_error_bucket(msr, f, it);
        }
    }

    return ap_pass_brigade(f->next, bb_in);
}
