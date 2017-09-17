

/*
 * Copyright (C) jiong
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_array_t                 *values;
    ngx_array_t                 *lengths;
} ngx_http_upstream_jump_consistent_hash_srv_conf_t;

typedef struct {
    struct sockaddr             *sockaddr;
    socklen_t                    socklen;
    ngx_str_t                    name;
} ngx_http_upstream_jump_consistent_hash_node;

typedef struct {
    ngx_http_upstream_jump_consistent_hash_node       *buckets;
    uint32_t                                           buckets_num;
} ngx_http_upstream_jump_consistent_hash_buckets;


typedef struct {
    ngx_http_upstream_jump_consistent_hash_buckets     *peers;
    uint32_t                                           point;
} ngx_http_upstream_jump_consistent_hash_peer_data_t;

static void * ngx_http_upstream_jump_consistent_hash_create_srv_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_upstream_init_jump_consistent_hash(ngx_conf_t*, 
        ngx_http_upstream_srv_conf_t*);
static ngx_int_t ngx_http_upstream_init_jump_consistent_hash_peer(ngx_http_request_t *r,
        ngx_http_upstream_srv_conf_t *us);

static char * ngx_http_upstream_jump_consistent_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static int32_t ngx_http_upstream_jump_consistent_hash_compute(uint64_t key, int32_t num_buckets);
static ngx_int_t ngx_http_upstream_get_jump_consistent_hash_peer(
        ngx_peer_connection_t*, void*);
static void ngx_http_upstream_free_jump_consistent_hash_peer(
        ngx_peer_connection_t*, void*, ngx_uint_t);

static ngx_command_t  ngx_http_upstream_jump_consistent_hash_commands[] = { 

    {   ngx_string("jump_consistent_hash"),
        NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
        ngx_http_upstream_jump_consistent_hash,
        0,
        0,
        NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_upstream_jump_consistent_hash_module_ctx = { 
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_jump_consistent_hash_create_srv_conf, /* create server configuration */
    NULL,                                              /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_upstream_jump_consistent_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_jump_consistent_hash_module_ctx, /* module context */
    ngx_http_upstream_jump_consistent_hash_commands,    /* module directives */
    NGX_HTTP_MODULE,                               /* module type */
    NULL,                                          /* init master */
    NULL,                                          /* init module */
    NULL,                                          /* init process */
    NULL,                                          /* init thread */
    NULL,                                          /* exit thread */
    NULL,                                          /* exit process */
    NULL,                                          /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_http_upstream_init_jump_consistent_hash(ngx_conf_t *cf, 
        ngx_http_upstream_srv_conf_t *us)
{

	ngx_uint_t                                        i, j, n;
	ngx_http_upstream_server_t                       *server;
	ngx_http_upstream_jump_consistent_hash_buckets    *buckets;

	buckets = ngx_pcalloc(cf->pool, 
            sizeof(ngx_http_upstream_jump_consistent_hash_buckets));

    us->peer.init = ngx_http_upstream_init_jump_consistent_hash_peer;

    if (!us->servers) {
        return NGX_ERROR;
    }

    server = us->servers->elts;

    for (n = 0, i = 0; i < us->servers->nelts; i++) {
        n += server[i].naddrs;
    }

    buckets->buckets = ngx_pcalloc(cf->pool, 
            sizeof(ngx_http_upstream_jump_consistent_hash_node) * n);

    for (i = 0; i < us->servers->nelts; i++) {
        for (j = 0; j < server[i].naddrs; j++) {
            buckets->buckets[buckets->buckets_num].sockaddr = server[i].addrs[j].sockaddr;
            buckets->buckets[buckets->buckets_num].socklen = server[i].addrs[j].socklen;
            buckets->buckets[buckets->buckets_num].name = server[i].addrs[j].name;
            buckets->buckets[buckets->buckets_num].name.data[server[i].addrs[j].name.len] = 0;
            buckets->buckets_num++;
        }
    }

    us->peer.data = buckets;

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_init_jump_consistent_hash_peer(ngx_http_request_t *r,
        ngx_http_upstream_srv_conf_t *us)
{
    ngx_str_t                                              evaluated_key_to_hash;
    ngx_http_upstream_jump_consistent_hash_srv_conf_t      *uchscf;
    ngx_http_upstream_jump_consistent_hash_peer_data_t     *uchpd;

    uchscf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_jump_consistent_hash_module);
    if (uchscf == NULL) {
        return NGX_ERROR;
    }

    uchpd = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_jump_consistent_hash_peer_data_t));
    if (uchpd == NULL) {
        return NGX_ERROR;
    }

    uchpd->peers = us->peer.data;

    if (ngx_http_script_run(r, &evaluated_key_to_hash, 
                uchscf->lengths->elts, 0, uchscf->values->elts) == NULL)
    {
        return NGX_ERROR;
    }

    uchpd->point = 
        ngx_crc32_long(evaluated_key_to_hash.data, evaluated_key_to_hash.len);

    r->upstream->peer.free = ngx_http_upstream_free_jump_consistent_hash_peer;
    r->upstream->peer.get  = ngx_http_upstream_get_jump_consistent_hash_peer;
    r->upstream->peer.data = uchpd;

    return NGX_OK;
}

static int32_t ngx_http_upstream_jump_consistent_hash_compute(uint64_t key, int32_t num_buckets) {
    int64_t b = -1, j = 0;
    while (j < num_buckets) {
        b = j;
        key = key * 2862933555777941757ULL + 1;
        j = (b + 1) * ((double)(1LL << 31) / (double)((key >> 33) + 1));
    }
    return b;
}

static ngx_int_t
ngx_http_upstream_get_jump_consistent_hash_peer(ngx_peer_connection_t *pc, 
        void *data)
{
    ngx_http_upstream_jump_consistent_hash_peer_data_t *uchpd = data;
	ngx_uint_t                                    offset;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "consistent hash point: %ui", uchpd->point);

    ngx_http_upstream_jump_consistent_hash_buckets  *buckets = uchpd->peers;
    offset = ngx_http_upstream_jump_consistent_hash_compute(uchpd->point, buckets->buckets_num);

    pc->cached = 0;
    pc->connection = NULL;

    pc->sockaddr = buckets->buckets[offset].sockaddr;
    pc->socklen  = buckets->buckets[offset].socklen;
    pc->name     = &buckets->buckets[offset].name;

    return NGX_OK;
}

static void 
ngx_http_upstream_free_jump_consistent_hash_peer(ngx_peer_connection_t *pc, void *data, 
        ngx_uint_t state) 
{
	return;
}

static void *
ngx_http_upstream_jump_consistent_hash_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_jump_consistent_hash_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_jump_consistent_hash_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_upstream_jump_consistent_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                                        *value;
    ngx_http_script_compile_t                         sc;
    ngx_http_upstream_srv_conf_t                     *uscf;
    ngx_http_upstream_jump_consistent_hash_srv_conf_t *uchscf;

    value = cf->args->elts;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    uchscf = ngx_http_conf_upstream_srv_conf(uscf,
                                          ngx_http_upstream_jump_consistent_hash_module);

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &uchscf->lengths;
    sc.values = &uchscf->values;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    uscf->peer.init_upstream = ngx_http_upstream_init_jump_consistent_hash;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE;
//        |NGX_HTTP_UPSTREAM_WEIGHT;

    return NGX_CONF_OK;
}
