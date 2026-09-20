
#include "msc_filters.h"
#include "msc_utils.h"


/* Moves up to nbytes worth of buckets from msr->body_replay_bb into pbbOut,
 * splitting at a bucket boundary so callers (e.g. mod_proxy_fcgi) that
 * relay the body onward in fixed-size chunks don't get handed more than
 * they asked for in one call. */
static apr_status_t replay_body_bytes(msc_t *msr, apr_bucket_brigade *pbbOut,
        apr_off_t nbytes)
{
    apr_bucket *split;
    apr_status_t rv;

    rv = apr_brigade_partition(msr->body_replay_bb, nbytes, &split);
    if (rv != APR_SUCCESS && rv != APR_INCOMPLETE)
    {
        return rv;
    }

    while (!APR_BRIGADE_EMPTY(msr->body_replay_bb)
            && APR_BRIGADE_FIRST(msr->body_replay_bb) != split)
    {
        apr_bucket *b = APR_BRIGADE_FIRST(msr->body_replay_bb);
        APR_BUCKET_REMOVE(b);
        APR_BRIGADE_INSERT_TAIL(pbbOut, b);
    }
    return APR_SUCCESS;
}

/* hook_request_late already drained the body from the network so
 * ModSecurity could inspect it before the real content handler runs.
 * Replay the buffered copy here instead of reading the (now empty)
 * network stream again, so the content handler still sees the body. Once
 * fully replayed, remove ourselves so later reads (or a body left unread
 * by the handler, drained via ap_discard_request_body) fall straight
 * through to the network filter, which is already at EOS. */
static apr_status_t replay_request_body(ap_filter_t *f,
        apr_bucket_brigade *pbbOut, ap_input_mode_t mode,
        apr_read_type_e block, apr_off_t nbytes)
{
    msc_t *msr = (msc_t *)f->ctx;
    apr_status_t rv;

    /* Nothing left to replay -- either this filter already replayed the
     * whole body, or (subrequests/internal redirects share the same msr
     * as the main request via retrieve_tx_context, while hook_insert_filter
     * adds a fresh MODSECURITY_IN instance per request) this is a later
     * request that never captured anything itself. Either way, remove
     * ourselves and delegate: an input filter must not return success with
     * an empty brigade. */
    if (APR_BRIGADE_EMPTY(msr->body_replay_bb))
    {
        ap_remove_input_filter(f);
        return ap_get_brigade(f->next, pbbOut, mode, block, nbytes);
    }

    if (mode == AP_MODE_READBYTES && nbytes > 0)
    {
        rv = replay_body_bytes(msr, pbbOut, nbytes);
    }
    else
    {
        APR_BRIGADE_CONCAT(pbbOut, msr->body_replay_bb);
        rv = APR_SUCCESS;
    }

    if (rv == APR_SUCCESS && APR_BRIGADE_EMPTY(msr->body_replay_bb))
    {
        ap_remove_input_filter(f);
    }
    return rv;
}

apr_status_t input_filter(ap_filter_t *f, apr_bucket_brigade *pbbOut,
        ap_input_mode_t mode, apr_read_type_e block, apr_off_t nbytes)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;

    apr_bucket_brigade *pbbTmp;
    int ret;

    msc_t *msr = (msc_t *)f->ctx;

    /* Do we have the context? */
    if (msr == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, f->r->server,
                "ModSecurity: Internal Error: msr is null in input filter.");
        ap_remove_input_filter(f);
        return send_error_bucket(msr, f, HTTP_INTERNAL_SERVER_ERROR);
    }

    if (mode == AP_MODE_EATCRLF)
    {
        pbbTmp = apr_brigade_create(r->pool, c->bucket_alloc);
        return ap_get_brigade(f->next, pbbTmp, mode, block, nbytes);
    }

    if (msr->request_body_processed)
    {
        return replay_request_body(f, pbbOut, mode, block, nbytes);
    }

    pbbTmp = apr_brigade_create(r->pool, c->bucket_alloc);

    ret = ap_get_brigade(f->next, pbbTmp, mode, block, nbytes);

    if (ret != APR_SUCCESS)
        return ret;

    while (!APR_BRIGADE_EMPTY(pbbTmp))
    {
        apr_bucket *pbktIn = APR_BRIGADE_FIRST(pbbTmp);
        apr_bucket *pbktOut;
        apr_bucket *pbktSave;
        const char *data;
        apr_size_t len;
        apr_size_t n;
        int it;

        if (APR_BUCKET_IS_EOS(pbktIn))
        {
            /* Mark that we've buffered the complete request body */
            /* The actual processing and intervention handling will be done
             * by hook_request_late, which can properly return HTTP status codes */
            msr->request_body_processed = 1;

            APR_BUCKET_REMOVE(pbktIn);
            APR_BRIGADE_INSERT_TAIL(pbbOut, pbktIn);
            APR_BRIGADE_INSERT_TAIL(msr->body_replay_bb,
                    apr_bucket_eos_create(c->bucket_alloc));
            break;
        }

        ret=apr_bucket_read(pbktIn, &data, &len, block);
        if (ret != APR_SUCCESS)
        {
            return ret;
        }

        /* Append body chunk - processing will happen in hook_request_late */
        msc_append_request_body(msr->t, data, len);

        pbktOut = apr_bucket_heap_create(data, len, 0, c->bucket_alloc);
        apr_bucket_copy(pbktOut, &pbktSave);
        APR_BRIGADE_INSERT_TAIL(msr->body_replay_bb, pbktSave);
        APR_BRIGADE_INSERT_TAIL(pbbOut, pbktOut);
        apr_bucket_delete(pbktIn);
    }
    return APR_SUCCESS;
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

