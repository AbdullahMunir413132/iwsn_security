/*
 * IWSN Security - Live Capture Module Implementation
 * Real-time packet capture and analysis using libpcap
 * 
 * Features:
 *   - Lists available network interfaces for user selection
 *   - Configurable BPF filters, duration, packet count limits
 *   - Real-time statistics display during capture
 *   - Graceful stop via Ctrl+C (SIGINT)
 *   - Fills pcap_stats_t for seamless integration with existing reporting
 */

#define _GNU_SOURCE  /* Required for struct sigaction, sigemptyset, etc. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <sys/time.h>
#include <pthread.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <time.h>
#include "live_capture.h"
#include "dpi_engine.h"
#include "mqtt_parser.h"
#include "rule_engine.h"

/*
 * Weak symbol declarations for rule engine functions and globals.
 * When live_capture.c is linked without rule_engine.c (e.g. the dpi_engine
 * binary), these resolve to zero/NULL so the periodic analysis block is
 * skipped at runtime without linker errors.
 */
extern int g_rule_engine_quiet __attribute__((weak));
extern void rule_engine_analyze_all_flows(rule_engine_t *, const dpi_engine_t *) __attribute__((weak));

#define LIVE_QUEUE_CAPACITY_DEFAULT 4096
#define LIVE_PIPELINE_MAX_WORKERS 16

typedef enum {
    LIVE_TASK_STAGE_IDS = 0,
    LIVE_TASK_STAGE_MQTT = 1
} live_task_stage_t;

typedef struct {
    parsed_packet_t parsed;
    uint8_t *raw_copy;
    uint32_t flow_hash;
    int mqtt_candidate;
    int ids_blocked;
} live_packet_task_t;

typedef struct {
    live_packet_task_t **items;
    uint32_t capacity;
    uint32_t head;
    uint32_t tail;
    uint32_t size;
    int stop;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
} live_packet_queue_t;

typedef struct live_pipeline_runtime_s live_pipeline_runtime_t;

typedef struct {
    live_pipeline_runtime_t *runtime;
    uint32_t worker_index;
} live_worker_arg_t;

struct live_pipeline_runtime_s {
    live_capture_ctx_t *ctx;
    live_packet_queue_t ids_queues[LIVE_PIPELINE_MAX_WORKERS];
    live_packet_queue_t mqtt_queues[LIVE_PIPELINE_MAX_WORKERS];
    pthread_t ids_threads[LIVE_PIPELINE_MAX_WORKERS];
    pthread_t mqtt_threads[LIVE_PIPELINE_MAX_WORKERS];
    int ids_thread_started[LIVE_PIPELINE_MAX_WORKERS];
    int mqtt_thread_started[LIVE_PIPELINE_MAX_WORKERS];
    uint32_t ids_worker_count;
    uint32_t mqtt_worker_count;
    pthread_mutex_t ids_callback_mutex;
    int ids_callback_mutex_initialized;
    uint64_t ids_queue_drops;
    uint64_t mqtt_queue_drops;
    uint64_t ids_processed;
    uint64_t mqtt_processed;
    uint64_t ids_queue_high_watermark;
    uint64_t mqtt_queue_high_watermark;
    live_worker_arg_t ids_args[LIVE_PIPELINE_MAX_WORKERS];
    live_worker_arg_t mqtt_args[LIVE_PIPELINE_MAX_WORKERS];
};

static int live_packet_is_mqtt_candidate(const parsed_packet_t *packet);

static void live_counter_inc_u64(uint64_t *value) {
    __sync_fetch_and_add(value, 1);
}

static void live_counter_max_u64(uint64_t *value, uint64_t candidate) {
    uint64_t current;
    do {
        current = __atomic_load_n(value, __ATOMIC_RELAXED);
        if (candidate <= current) {
            return;
        }
    } while (!__sync_bool_compare_and_swap(value, current, candidate));
}

static uint32_t live_normalize_worker_count(uint32_t requested, uint32_t default_value) {
    if (requested == 0) {
        return default_value;
    }
    if (requested > LIVE_PIPELINE_MAX_WORKERS) {
        return LIVE_PIPELINE_MAX_WORKERS;
    }
    return requested;
}

static uint32_t live_parse_env_u32(const char *name, uint32_t fallback, uint32_t min_value, uint32_t max_value) {
    const char *raw = getenv(name);
    char *endptr = NULL;
    unsigned long parsed;

    if (!raw || raw[0] == '\0') {
        return fallback;
    }

    errno = 0;
    parsed = strtoul(raw, &endptr, 10);
    if (errno != 0 || endptr == raw || *endptr != '\0' || parsed > UINT_MAX) {
        return fallback;
    }

    if (parsed < min_value) {
        return min_value;
    }
    if (parsed > max_value) {
        return max_value;
    }
    return (uint32_t)parsed;
}

static int live_parse_env_bool(const char *name, int fallback) {
    const char *raw = getenv(name);
    if (!raw || raw[0] == '\0') {
        return fallback;
    }

    if (strcasecmp(raw, "1") == 0 ||
        strcasecmp(raw, "true") == 0 ||
        strcasecmp(raw, "yes") == 0 ||
        strcasecmp(raw, "y") == 0 ||
        strcasecmp(raw, "on") == 0) {
        return 1;
    }

    if (strcasecmp(raw, "0") == 0 ||
        strcasecmp(raw, "false") == 0 ||
        strcasecmp(raw, "no") == 0 ||
        strcasecmp(raw, "n") == 0 ||
        strcasecmp(raw, "off") == 0) {
        return 0;
    }

    return fallback;
}

static uint32_t live_flow_hash(const parsed_packet_t *parsed) {
    uint32_t h = 2166136261u;

    if (!parsed) {
        return 0;
    }

    h ^= parsed->layer3.src_ip;
    h *= 16777619u;
    h ^= parsed->layer3.dst_ip;
    h *= 16777619u;
    h ^= parsed->layer4.src_port;
    h *= 16777619u;
    h ^= parsed->layer4.dst_port;
    h *= 16777619u;
    h ^= parsed->layer3.protocol;
    h *= 16777619u;

    return h;
}

static live_packet_task_t *live_packet_task_create(const parsed_packet_t *parsed, int copy_raw_data) {
    live_packet_task_t *task = (live_packet_task_t *)calloc(1, sizeof(live_packet_task_t));
    if (!task) {
        return NULL;
    }

    memcpy(&task->parsed, parsed, sizeof(parsed_packet_t));
    task->parsed.flow = NULL;

    task->flow_hash = live_flow_hash(parsed);
    task->mqtt_candidate = live_packet_is_mqtt_candidate(parsed);
    task->ids_blocked = 0;

    if (copy_raw_data && parsed->raw_data && parsed->raw_data_len > 0) {
        task->raw_copy = (uint8_t *)malloc(parsed->raw_data_len);
        if (!task->raw_copy) {
            free(task);
            return NULL;
        }
        memcpy(task->raw_copy, parsed->raw_data, parsed->raw_data_len);
        task->parsed.raw_data = task->raw_copy;
    }

    return task;
}

static void live_packet_task_destroy(live_packet_task_t *task) {
    if (!task) {
        return;
    }
    free(task->raw_copy);
    free(task);
}

static int live_packet_queue_init(live_packet_queue_t *q, uint32_t capacity) {
    memset(q, 0, sizeof(*q));
    q->items = (live_packet_task_t **)calloc(capacity, sizeof(live_packet_task_t *));
    if (!q->items) {
        return -1;
    }
    q->capacity = capacity;
    if (pthread_mutex_init(&q->mutex, NULL) != 0) {
        free(q->items);
        q->items = NULL;
        return -1;
    }
    if (pthread_cond_init(&q->not_empty, NULL) != 0) {
        pthread_mutex_destroy(&q->mutex);
        free(q->items);
        q->items = NULL;
        return -1;
    }
    return 0;
}

static void live_packet_queue_stop(live_packet_queue_t *q) {
    pthread_mutex_lock(&q->mutex);
    q->stop = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
}

static void live_packet_queue_destroy(live_packet_queue_t *q) {
    uint32_t i;
    if (!q->items) {
        return;
    }

    for (i = 0; i < q->capacity; i++) {
        if (q->items[i]) {
            live_packet_task_destroy(q->items[i]);
            q->items[i] = NULL;
        }
    }

    pthread_cond_destroy(&q->not_empty);
    pthread_mutex_destroy(&q->mutex);
    free(q->items);
    q->items = NULL;
}

static int live_packet_queue_push_nowait(live_packet_queue_t *q, live_packet_task_t *task) {
    int rc = 0;
    pthread_mutex_lock(&q->mutex);
    if (q->size >= q->capacity || q->stop) {
        rc = -1;
    } else {
        q->items[q->tail] = task;
        q->tail = (q->tail + 1) % q->capacity;
        q->size++;
        pthread_cond_signal(&q->not_empty);
    }
    pthread_mutex_unlock(&q->mutex);
    return rc;
}

static uint32_t live_packet_queue_size(live_packet_queue_t *q) {
    uint32_t size;
    pthread_mutex_lock(&q->mutex);
    size = q->size;
    pthread_mutex_unlock(&q->mutex);
    return size;
}

static live_packet_task_t *live_packet_queue_pop_wait(live_packet_queue_t *q) {
    live_packet_task_t *task = NULL;

    pthread_mutex_lock(&q->mutex);
    while (q->size == 0 && !q->stop) {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }

    if (q->size > 0) {
        task = q->items[q->head];
        q->items[q->head] = NULL;
        q->head = (q->head + 1) % q->capacity;
        q->size--;
    }

    pthread_mutex_unlock(&q->mutex);
    return task;
}

static int live_packet_is_mqtt_candidate(const parsed_packet_t *packet) {
    return packet && (packet->layer4.dst_port == 1883 ||
                      packet->layer4.src_port == 1883 ||
                      packet->layer4.dst_port == 8883 ||
                      packet->layer4.src_port == 8883);
}

static void *live_ids_worker(void *arg) {
    live_worker_arg_t *worker_arg = (live_worker_arg_t *)arg;
    live_pipeline_runtime_t *rt = worker_arg->runtime;
    live_capture_ctx_t *ctx = rt->ctx;
    uint32_t worker_index = worker_arg->worker_index;

    while (!g_live_capture_stop) {
        live_packet_task_t *task = live_packet_queue_pop_wait(&rt->ids_queues[worker_index]);

        if (!task) {
            if (rt->ids_queues[worker_index].stop) {
                break;
            }
            continue;
        }

        if (ctx->ids_mode && ctx->ids_callback && ctx->rule_engine) {
            pthread_mutex_lock(&rt->ids_callback_mutex);
            ctx->ids_callback(ctx->rule_engine, &task->parsed);
            pthread_mutex_unlock(&rt->ids_callback_mutex);
        }

        if (ctx->ids_mode && ctx->rule_engine && ctx->ids_is_blocked_callback) {
            pthread_mutex_lock(&rt->ids_callback_mutex);
            task->ids_blocked = ctx->ids_is_blocked_callback(ctx->rule_engine, task->parsed.layer3.src_ip);
            pthread_mutex_unlock(&rt->ids_callback_mutex);
        }

        if (ctx->mqtt_mode && ctx->mqtt_callback && task->mqtt_candidate && !task->ids_blocked) {
            uint32_t mqtt_index = task->flow_hash % rt->mqtt_worker_count;
            if (live_packet_queue_push_nowait(&rt->mqtt_queues[mqtt_index], task) != 0) {
                live_counter_inc_u64(&rt->mqtt_queue_drops);
                live_packet_task_destroy(task);
            } else {
                uint32_t qsize = live_packet_queue_size(&rt->mqtt_queues[mqtt_index]);
                live_counter_max_u64(&rt->mqtt_queue_high_watermark, qsize);
            }
        } else {
            live_packet_task_destroy(task);
        }

        live_counter_inc_u64(&rt->ids_processed);
    }

    return NULL;
}

static void *live_mqtt_worker(void *arg) {
    live_worker_arg_t *worker_arg = (live_worker_arg_t *)arg;
    live_pipeline_runtime_t *rt = worker_arg->runtime;
    live_capture_ctx_t *ctx = rt->ctx;
    uint32_t worker_index = worker_arg->worker_index;

    while (!g_live_capture_stop) {
        live_packet_task_t *task = live_packet_queue_pop_wait(&rt->mqtt_queues[worker_index]);
        if (!task) {
            if (rt->mqtt_queues[worker_index].stop) {
                break;
            }
            continue;
        }

        if (ctx->mqtt_mode && ctx->mqtt_callback) {
            ctx->mqtt_callback(ctx->mqtt_context, &task->parsed);
        }

        live_packet_task_destroy(task);
        live_counter_inc_u64(&rt->mqtt_processed);
    }

    return NULL;
}

static int live_pipeline_start(live_capture_ctx_t *ctx, live_pipeline_runtime_t *rt) {
    uint32_t i;

    memset(rt, 0, sizeof(*rt));
    rt->ctx = ctx;
    rt->ids_worker_count = live_normalize_worker_count(ctx->config.ids_workers, 1);
    rt->mqtt_worker_count = live_normalize_worker_count(ctx->config.mqtt_workers, 2);

    if (pthread_mutex_init(&rt->ids_callback_mutex, NULL) != 0) {
        return -1;
    }
    rt->ids_callback_mutex_initialized = 1;

    for (i = 0; i < rt->ids_worker_count; i++) {
        if (live_packet_queue_init(&rt->ids_queues[i], ctx->config.pipeline_queue_capacity) != 0) {
            goto fail;
        }
    }
    for (i = 0; i < rt->mqtt_worker_count; i++) {
        if (live_packet_queue_init(&rt->mqtt_queues[i], ctx->config.pipeline_queue_capacity) != 0) {
            goto fail;
        }
    }

    for (i = 0; i < rt->ids_worker_count; i++) {
        rt->ids_args[i].runtime = rt;
        rt->ids_args[i].worker_index = i;
        if (pthread_create(&rt->ids_threads[i], NULL, live_ids_worker, &rt->ids_args[i]) != 0) {
            goto fail;
        }
        rt->ids_thread_started[i] = 1;
    }

    for (i = 0; i < rt->mqtt_worker_count; i++) {
        rt->mqtt_args[i].runtime = rt;
        rt->mqtt_args[i].worker_index = i;
        if (pthread_create(&rt->mqtt_threads[i], NULL, live_mqtt_worker, &rt->mqtt_args[i]) != 0) {
            goto fail;
        }
        rt->mqtt_thread_started[i] = 1;
    }

    return 0;

fail:
    for (i = 0; i < rt->ids_worker_count; i++) {
        live_packet_queue_stop(&rt->ids_queues[i]);
    }
    for (i = 0; i < rt->mqtt_worker_count; i++) {
        live_packet_queue_stop(&rt->mqtt_queues[i]);
    }

    for (i = 0; i < rt->ids_worker_count; i++) {
        if (rt->ids_thread_started[i]) {
            pthread_join(rt->ids_threads[i], NULL);
            rt->ids_thread_started[i] = 0;
        }
    }
    for (i = 0; i < rt->mqtt_worker_count; i++) {
        if (rt->mqtt_thread_started[i]) {
            pthread_join(rt->mqtt_threads[i], NULL);
            rt->mqtt_thread_started[i] = 0;
        }
    }

    for (i = 0; i < LIVE_PIPELINE_MAX_WORKERS; i++) {
        live_packet_queue_destroy(&rt->ids_queues[i]);
        live_packet_queue_destroy(&rt->mqtt_queues[i]);
    }

    if (rt->ids_callback_mutex_initialized) {
        pthread_mutex_destroy(&rt->ids_callback_mutex);
        rt->ids_callback_mutex_initialized = 0;
    }

    return -1;
}

static void live_pipeline_stop(live_pipeline_runtime_t *rt) {
    uint32_t i;

    for (i = 0; i < rt->ids_worker_count; i++) {
        live_packet_queue_stop(&rt->ids_queues[i]);
    }
    for (i = 0; i < rt->mqtt_worker_count; i++) {
        live_packet_queue_stop(&rt->mqtt_queues[i]);
    }

    for (i = 0; i < rt->ids_worker_count; i++) {
        if (rt->ids_thread_started[i]) {
            pthread_join(rt->ids_threads[i], NULL);
            rt->ids_thread_started[i] = 0;
        }
    }
    for (i = 0; i < rt->mqtt_worker_count; i++) {
        if (rt->mqtt_thread_started[i]) {
            pthread_join(rt->mqtt_threads[i], NULL);
            rt->mqtt_thread_started[i] = 0;
        }
    }

    for (i = 0; i < rt->ids_worker_count; i++) {
        live_packet_queue_destroy(&rt->ids_queues[i]);
    }
    for (i = 0; i < rt->mqtt_worker_count; i++) {
        live_packet_queue_destroy(&rt->mqtt_queues[i]);
    }

    if (rt->ids_callback_mutex_initialized) {
        pthread_mutex_destroy(&rt->ids_callback_mutex);
        rt->ids_callback_mutex_initialized = 0;
    }
}

static uint32_t live_pipeline_total_queue_depth(live_pipeline_runtime_t *rt, live_task_stage_t stage) {
    uint32_t i;
    uint32_t total = 0;

    if (stage == LIVE_TASK_STAGE_IDS) {
        for (i = 0; i < rt->ids_worker_count; i++) {
            total += live_packet_queue_size(&rt->ids_queues[i]);
        }
    } else {
        for (i = 0; i < rt->mqtt_worker_count; i++) {
            total += live_packet_queue_size(&rt->mqtt_queues[i]);
        }
    }

    return total;
}

/* ========== Real-time Metrics Snapshot Writer ========== */

static void live_capture_write_metrics_snapshot(const live_capture_ctx_t *ctx) {
    if (!ctx || ctx->realtime_metrics_file[0] == '\0') {
        return;
    }

    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - ctx->stats.capture_start.tv_sec) +
                     (now.tv_usec - ctx->stats.capture_start.tv_usec) / 1000000.0;

    double pps = (elapsed > 0.0) ? (ctx->stats.packets_captured / elapsed) : 0.0;
    double mbps = (elapsed > 0.0) ? ((ctx->stats.bytes_captured * 8.0) / (elapsed * 1000000.0)) : 0.0;

    /*
     * Real-time attack detection: run the full flow-level analysis against
     * current DPI flows every 5 seconds so that attacks are visible in the
     * live snapshot immediately, not just after capture ends.
     *
     * add_detection() deduplicates by (attack_type, attacker_ip, target_ip)
     * so calling this repeatedly is safe — attacks_by_type is incremented
     * only on the first detection of each unique (type, src, dst) tuple.
     * g_rule_engine_quiet suppresses progress banners during periodic calls.
     */
    if (ctx->ids_mode && ctx->rule_engine && ctx->dpi_engine
            && rule_engine_analyze_all_flows) {
        static time_t last_ids_analysis_time = 0;
        time_t now_t = (time_t)now.tv_sec;
        if (now_t - last_ids_analysis_time >= 5) {
            last_ids_analysis_time = now_t;
            g_rule_engine_quiet = 1;
            rule_engine_analyze_all_flows((rule_engine_t *)ctx->rule_engine, ctx->dpi_engine);
            g_rule_engine_quiet = 0;
        }
    }

    uint64_t ids_packets = 0;
    uint64_t ids_attacks = 0;
    uint32_t ids_blocked_ips = 0;
    if (ctx->ids_mode && ctx->rule_engine) {
        const rule_engine_t *rule = (const rule_engine_t *)ctx->rule_engine;
        ids_packets = rule->total_packets_analyzed;
        ids_attacks = rule->total_attacks_detected;
        ids_blocked_ips = rule->blocked_ip_count;
    }

    mqtt_statistics_t mqtt_stats;
    memset(&mqtt_stats, 0, sizeof(mqtt_stats));
    mqtt_get_statistics(&mqtt_stats);

    /* Real-time protocol distribution (packet-weighted per current flows) */
    uint64_t pd_tcp = 0;
    uint64_t pd_udp = 0;
    uint64_t pd_icmp = 0;
    uint64_t pd_http = 0;
    uint64_t pd_https = 0;
    uint64_t pd_dns = 0;
    uint64_t pd_mqtt = 0;
    uint64_t pd_tls = 0;
    uint64_t pd_unknown = 0;

    if (ctx->dpi_engine) {
        for (uint32_t i = 0; i < ctx->dpi_engine->flow_count; i++) {
            const flow_stats_t *flow = &ctx->dpi_engine->flows[i];
            uint64_t weight = flow->total_packets;
            const char *pname = flow->protocol_name;

            if (weight == 0) continue;

            if (pname && pname[0] != '\0' && strcasecmp(pname, "Unknown") != 0) {
                if (strcasestr(pname, "MQTT"))  { pd_mqtt += weight; continue; }
                if (strcasestr(pname, "DNS"))   { pd_dns += weight;  continue; }
                if (strcasestr(pname, "HTTPS")) { pd_https += weight; continue; }
                if (strcasestr(pname, "HTTP"))  { pd_http += weight; continue; }
                if (strcasestr(pname, "TLS") || strcasestr(pname, "SSL")) {
                    pd_tls += weight;
                    continue;
                }
            }

            switch (flow->protocol) {
                case IPPROTO_TCP:  pd_tcp += weight; break;
                case IPPROTO_UDP:  pd_udp += weight; break;
                case IPPROTO_ICMP: pd_icmp += weight; break;
                default:           pd_unknown += weight; break;
            }
        }
    }

    /* Collect per-attack-type counts from the rule engine for real-time panels */
    uint64_t at_syn_flood         = 0;
    uint64_t at_udp_flood         = 0;
    uint64_t at_http_flood        = 0;
    uint64_t at_icmp_flood        = 0;
    uint64_t at_dns_amp           = 0;
    uint64_t at_ntp_amp           = 0;
    uint64_t at_smurf             = 0;
    uint64_t at_fraggle           = 0;
    uint64_t at_ping_of_death     = 0;
    uint64_t at_land              = 0;
    uint64_t at_teardrop          = 0;
    uint64_t at_ip_spoofing       = 0;
    uint64_t at_tcp_syn_scan      = 0;
    uint64_t at_tcp_connect_scan  = 0;
    uint64_t at_udp_scan          = 0;
    uint64_t at_xmas_scan         = 0;
    uint64_t at_null_scan         = 0;
    uint64_t at_fin_scan          = 0;
    uint64_t at_port_scan_generic = 0;
    uint64_t at_rudy              = 0;
    uint64_t at_slowloris         = 0;
    uint64_t at_arp_spoofing      = 0;

    if (ctx->ids_mode && ctx->rule_engine) {
        const rule_engine_t *rule = (const rule_engine_t *)ctx->rule_engine;
        at_syn_flood         = rule->attacks_by_type[ATTACK_SYN_FLOOD];
        at_udp_flood         = rule->attacks_by_type[ATTACK_UDP_FLOOD];
        at_http_flood        = rule->attacks_by_type[ATTACK_HTTP_FLOOD];
        at_icmp_flood        = rule->attacks_by_type[ATTACK_ICMP_FLOOD];
        at_dns_amp           = rule->attacks_by_type[ATTACK_DNS_AMPLIFICATION];
        at_ntp_amp           = rule->attacks_by_type[ATTACK_NTP_AMPLIFICATION];
        at_smurf             = rule->attacks_by_type[ATTACK_SMURF];
        at_fraggle           = rule->attacks_by_type[ATTACK_FRAGGLE];
        at_ping_of_death     = rule->attacks_by_type[ATTACK_PING_OF_DEATH];
        at_land              = rule->attacks_by_type[ATTACK_LAND_ATTACK];
        at_teardrop          = rule->attacks_by_type[ATTACK_TEARDROP];
        at_ip_spoofing       = rule->attacks_by_type[ATTACK_IP_SPOOFING];
        at_tcp_syn_scan      = rule->attacks_by_type[ATTACK_TCP_SYN_SCAN];
        at_tcp_connect_scan  = rule->attacks_by_type[ATTACK_TCP_CONNECT_SCAN];
        at_udp_scan          = rule->attacks_by_type[ATTACK_UDP_SCAN];
        at_xmas_scan         = rule->attacks_by_type[ATTACK_XMAS_SCAN];
        at_null_scan         = rule->attacks_by_type[ATTACK_NULL_SCAN];
        at_fin_scan          = rule->attacks_by_type[ATTACK_FIN_SCAN];
        at_port_scan_generic = rule->attacks_by_type[ATTACK_PORT_SCAN_GENERIC];
        at_rudy              = rule->attacks_by_type[ATTACK_RUDY];
        at_slowloris         = rule->attacks_by_type[ATTACK_SLOWLORIS];
        at_arp_spoofing      = rule->attacks_by_type[ATTACK_ARP_SPOOFING];
    }

    char tmp_file[320];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp", ctx->realtime_metrics_file);

    FILE *fp = fopen(tmp_file, "w");
    if (!fp) {
        return;
    }

    fprintf(fp,
            "{\n"
            "  \"timestamp_unix\": %ld,\n"
            "  \"capture\": {\n"
            "    \"packets_captured\": %lu,\n"
            "    \"bytes_captured\": %lu,\n"
            "    \"packets_per_second\": %.3f,\n"
            "    \"throughput_mbps\": %.6f,\n"
            "    \"elapsed_seconds\": %.3f\n"
            "  },\n"
            "  \"dpi\": {\n"
            "    \"flows\": %u,\n"
            "    \"total_packets\": %lu,\n"
            "    \"total_bytes\": %lu,\n"
            "    \"l2_parsed\": %lu,\n"
            "    \"l3_parsed\": %lu,\n"
            "    \"l4_parsed\": %lu,\n"
            "    \"l5_parsed\": %lu\n"
            "  },\n"
            "  \"protocol_distribution\": {\n"
            "    \"tcp\": %lu,\n"
            "    \"udp\": %lu,\n"
            "    \"icmp\": %lu,\n"
            "    \"http\": %lu,\n"
            "    \"https\": %lu,\n"
            "    \"dns\": %lu,\n"
            "    \"mqtt\": %lu,\n"
            "    \"tls\": %lu,\n"
            "    \"unknown\": %lu\n"
            "  },\n"
            "  \"ids\": {\n"
            "    \"packets_analyzed\": %lu,\n"
            "    \"attacks_detected\": %lu,\n"
            "    \"blocked_ips\": %u\n"
            "  },\n"
            "  \"mqtt\": {\n"
            "    \"total_packets\": %lu,\n"
            "    \"connect_count\": %lu,\n"
            "    \"publish_count\": %lu,\n"
            "    \"subscribe_count\": %lu,\n"
            "    \"pingreq_count\": %lu,\n"
            "    \"disconnect_count\": %lu,\n"
            "    \"malformed_packets\": %lu\n"
            "  },\n"
            "  \"attacks_by_type\": {\n"
            "    \"syn_flood\": %lu,\n"
            "    \"udp_flood\": %lu,\n"
            "    \"http_flood\": %lu,\n"
            "    \"icmp_flood\": %lu,\n"
            "    \"dns_amplification\": %lu,\n"
            "    \"ntp_amplification\": %lu,\n"
            "    \"smurf_attack\": %lu,\n"
            "    \"fraggle_attack\": %lu,\n"
            "    \"ping_of_death\": %lu,\n"
            "    \"land_attack\": %lu,\n"
            "    \"teardrop_attack\": %lu,\n"
            "    \"ip_spoofing\": %lu,\n"
            "    \"tcp_syn_scan\": %lu,\n"
            "    \"tcp_connect_scan\": %lu,\n"
            "    \"udp_scan\": %lu,\n"
            "    \"xmas_scan\": %lu,\n"
            "    \"null_scan\": %lu,\n"
            "    \"fin_scan\": %lu,\n"
            "    \"port_scan_generic\": %lu,\n"
            "    \"rudy_attack\": %lu,\n"
            "    \"slowloris\": %lu,\n"
            "    \"arp_spoofing\": %lu\n"
            "  }\n"
            "}\n",
            (long)now.tv_sec,
            ctx->stats.packets_captured,
            ctx->stats.bytes_captured,
            pps,
            mbps,
            elapsed,
            ctx->dpi_engine->flow_count,
            ctx->dpi_engine->total_packets,
            ctx->dpi_engine->total_bytes,
            ctx->dpi_engine->l2_parsed,
            ctx->dpi_engine->l3_parsed,
            ctx->dpi_engine->l4_parsed,
            ctx->dpi_engine->l5_parsed,
            pd_tcp,
            pd_udp,
            pd_icmp,
            pd_http,
            pd_https,
            pd_dns,
            pd_mqtt,
            pd_tls,
            pd_unknown,
            ids_packets,
            ids_attacks,
            ids_blocked_ips,
            mqtt_stats.total_packets,
            mqtt_stats.connect_count,
            mqtt_stats.publish_count,
            mqtt_stats.subscribe_count,
            mqtt_stats.pingreq_count,
            mqtt_stats.disconnect_count,
            mqtt_stats.malformed_packets,
            at_syn_flood,
            at_udp_flood,
            at_http_flood,
            at_icmp_flood,
            at_dns_amp,
            at_ntp_amp,
            at_smurf,
            at_fraggle,
            at_ping_of_death,
            at_land,
            at_teardrop,
            at_ip_spoofing,
            at_tcp_syn_scan,
            at_tcp_connect_scan,
            at_udp_scan,
            at_xmas_scan,
            at_null_scan,
            at_fin_scan,
            at_port_scan_generic,
            at_rudy,
            at_slowloris,
            at_arp_spoofing);

    fclose(fp);
    rename(tmp_file, ctx->realtime_metrics_file);
}

/* ========== Global Stop Flag for Signal Handler ========== */
volatile sig_atomic_t g_live_capture_stop = 0;

void live_capture_signal_handler(int signum) {
    (void)signum;
    g_live_capture_stop = 1;
    printf("\n\n[LIVE CAPTURE] Ctrl+C received — stopping capture gracefully...\n");
}

/* ========== Mode Selection Prompt ========== */

capture_mode_t prompt_capture_mode(void) {
    const char *mode_env = getenv("IWSN_CAPTURE_MODE");
    int choice = 0;

    if (mode_env && mode_env[0] != '\0') {
        if (strcasecmp(mode_env, "live") == 0 || strcasecmp(mode_env, "2") == 0) {
            printf("\n  [Auto] IWSN_CAPTURE_MODE=live -> Real-Time Capture\n\n");
            return CAPTURE_MODE_LIVE;
        }
        if (strcasecmp(mode_env, "pcap") == 0 || strcasecmp(mode_env, "offline") == 0 ||
            strcasecmp(mode_env, "1") == 0) {
            printf("\n  [Auto] IWSN_CAPTURE_MODE=pcap -> PCAP File Analysis\n\n");
            return CAPTURE_MODE_PCAP;
        }
    }

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                  SELECT CAPTURE MODE                           ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║                                                                ║\n");
    printf("║   [1]  PCAP File Analysis  (Offline Mode)                      ║\n");
    printf("║        Analyze a previously captured .pcap file                ║\n");
    printf("║                                                                ║\n");
    printf("║   [2]  Real-Time Capture   (Live Mode)                         ║\n");
    printf("║        Capture and analyze packets from a live interface       ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    while (1) {
        printf("  Enter your choice [1 or 2]: ");
        fflush(stdout);
        if (scanf("%d", &choice) != 1) {
            // Flush invalid input
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            printf("  ⚠ Invalid input. Please enter 1 or 2.\n");
            continue;
        }
        // Consume trailing newline
        int c;
        while ((c = getchar()) != '\n' && c != EOF);

        if (choice == 1) {
            printf("\n  ✓ Selected: PCAP File Analysis (Offline Mode)\n\n");
            return CAPTURE_MODE_PCAP;
        } else if (choice == 2) {
            printf("\n  ✓ Selected: Real-Time Capture (Live Mode)\n\n");
            return CAPTURE_MODE_LIVE;
        } else {
            printf("  ⚠ Invalid choice. Please enter 1 or 2.\n");
        }
    }
}

/* ========== List Network Interfaces ========== */

int list_network_interfaces(void) {
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[Error] Cannot enumerate interfaces: %s\n", errbuf);
        return -1;
    }

    printf("  ┌─────────────────────────────────────────────────────────┐\n");
    printf("  │              Available Network Interfaces                │\n");
    printf("  ├────┬───────────────┬────────────────────────────────────┤\n");
    printf("  │ #  │ Interface     │ Description / Address              │\n");
    printf("  ├────┼───────────────┼────────────────────────────────────┤\n");

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        count++;

        // Try to get the first IPv4 address
        char addr_str[64] = "N/A";
        if (dev->addresses) {
            pcap_addr_t *a;
            for (a = dev->addresses; a != NULL; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                    inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
                    break;
                }
            }
        }

        const char *desc = dev->description ? dev->description : addr_str;
        printf("  │ %-2d │ %-13s │ %-34s │\n", count, dev->name, desc);
    }

    printf("  └────┴───────────────┴────────────────────────────────────┘\n");

    if (count == 0) {
        printf("  ⚠ No interfaces found. Are you running as root/sudo?\n");
    }

    pcap_freealldevs(alldevs);
    return count;
}

/* ========== Select Network Interface ========== */

int select_network_interface(char *iface_name, size_t name_len) {
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[Error] Cannot enumerate interfaces: %s\n", errbuf);
        return -1;
    }

    // Count interfaces
    int count = 0;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        count++;
    }

    if (count == 0) {
        printf("  ⚠ No interfaces found. Run with sudo for access.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\n");
    list_network_interfaces();
    printf("\n");

    int choice = 0;
    while (1) {
        printf("  Select interface [1-%d]: ", count);
        fflush(stdout);
        if (scanf("%d", &choice) != 1) {
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            printf("  ⚠ Invalid input. Enter a number.\n");
            continue;
        }
        int c;
        while ((c = getchar()) != '\n' && c != EOF);

        if (choice >= 1 && choice <= count) {
            break;
        }
        printf("  ⚠ Invalid choice. Enter 1-%d.\n", count);
    }

    // Navigate to the selected interface
    dev = alldevs;
    for (int i = 1; i < choice; i++) {
        dev = dev->next;
    }

    strncpy(iface_name, dev->name, name_len - 1);
    iface_name[name_len - 1] = '\0';

    printf("  ✓ Selected interface: %s\n", iface_name);

    pcap_freealldevs(alldevs);
    return 0;
}

/* ========== Configuration Defaults ========== */

void live_capture_config_defaults(live_capture_config_t *config) {
    memset(config, 0, sizeof(live_capture_config_t));
    config->max_packets = 0;          // Unlimited
    config->duration_seconds = 0;     // Unlimited
    config->promiscuous = 1;          // Promiscuous mode on
    config->snap_length = 65535;      // Full packet capture
    config->read_timeout_ms = 1000;   // 1 second timeout for pcap_next_ex
    config->pipeline_queue_capacity = LIVE_QUEUE_CAPACITY_DEFAULT;
    config->ids_workers = 1;
    config->mqtt_workers = 2;
    config->bpf_filter[0] = '\0';

    config->pipeline_queue_capacity = live_parse_env_u32(
        "IWSN_PIPELINE_QUEUE_CAPACITY",
        config->pipeline_queue_capacity,
        64,
        65535
    );
    config->ids_workers = live_parse_env_u32(
        "IWSN_IDS_WORKERS",
        config->ids_workers,
        1,
        LIVE_PIPELINE_MAX_WORKERS
    );
    config->mqtt_workers = live_parse_env_u32(
        "IWSN_MQTT_WORKERS",
        config->mqtt_workers,
        1,
        LIVE_PIPELINE_MAX_WORKERS
    );
}

/* ========== Interactive Configuration Prompt ========== */

int prompt_live_capture_config(live_capture_config_t *config) {
    const char *iface_env;
    const char *filter_env;
    int auto_config = 0;
    char input_buf[512];

    live_capture_config_defaults(config);

    iface_env = getenv("IWSN_LIVE_INTERFACE");
    filter_env = getenv("IWSN_LIVE_BPF_FILTER");

    config->max_packets = live_parse_env_u32(
        "IWSN_LIVE_MAX_PACKETS",
        config->max_packets,
        0,
        UINT_MAX
    );
    config->duration_seconds = live_parse_env_u32(
        "IWSN_LIVE_DURATION_SECONDS",
        config->duration_seconds,
        0,
        UINT_MAX
    );
    config->promiscuous = live_parse_env_bool("IWSN_LIVE_PROMISCUOUS", config->promiscuous);

    if (filter_env && filter_env[0] != '\0') {
        snprintf(config->bpf_filter, sizeof(config->bpf_filter), "%s", filter_env);
        auto_config = 1;
    }

    // 1. Select interface
    if (iface_env && iface_env[0] != '\0') {
        snprintf(config->interface_name, sizeof(config->interface_name), "%s", iface_env);
        auto_config = 1;
    } else {
        if (select_network_interface(config->interface_name, sizeof(config->interface_name)) != 0) {
            return -1;
        }
    }

    if (getenv("IWSN_AUTOMATED_LIVE_CONFIG")) {
        auto_config = 1;
    }

    if (auto_config) {
        printf("\n  [Auto] Using environment-driven live configuration\n");
        printf("  [Auto] Interface: %s\n", config->interface_name);
        printf("  [Auto] Filter: %s\n", strlen(config->bpf_filter) > 0 ? config->bpf_filter : "(none)");
        printf("  [Auto] Max Packets: %u\n", config->max_packets);
        printf("  [Auto] Duration: %u sec\n", config->duration_seconds);
        printf("  [Auto] Promiscuous: %s\n", config->promiscuous ? "YES" : "NO");
        printf("  [Auto] IDS Workers: %u | MQTT Workers: %u | Queue: %u\n\n",
               config->ids_workers,
               config->mqtt_workers,
               config->pipeline_queue_capacity);
        return 0;
    }

    // 2. BPF Filter (optional)
    printf("\n  Enter BPF filter (e.g., 'tcp port 1883', 'host 192.168.1.1').\n");
    printf("  Press Enter for no filter (capture all traffic): ");
    fflush(stdout);
    if (fgets(input_buf, sizeof(input_buf), stdin) != NULL) {
        // Remove trailing newline
        input_buf[strcspn(input_buf, "\n")] = '\0';
        if (strlen(input_buf) > 0) {
            snprintf(config->bpf_filter, sizeof(config->bpf_filter), "%s", input_buf);
            printf("  ✓ BPF filter: %s\n", config->bpf_filter);
        } else {
            printf("  ✓ No filter applied (capturing all traffic)\n");
        }
    }

    // 3. Max packets
    printf("\n  Max packets to capture (0 = unlimited, Ctrl+C to stop): ");
    fflush(stdout);
    if (fgets(input_buf, sizeof(input_buf), stdin) != NULL) {
        input_buf[strcspn(input_buf, "\n")] = '\0';
        if (strlen(input_buf) > 0) {
            config->max_packets = (uint32_t)atoi(input_buf);
        }
    }
    if (config->max_packets == 0) {
        printf("  ✓ Unlimited packets (press Ctrl+C to stop)\n");
    } else {
        printf("  ✓ Will capture up to %u packets\n", config->max_packets);
    }

    // 4. Duration
    printf("\n  Capture duration in seconds (0 = unlimited, Ctrl+C to stop): ");
    fflush(stdout);
    if (fgets(input_buf, sizeof(input_buf), stdin) != NULL) {
        input_buf[strcspn(input_buf, "\n")] = '\0';
        if (strlen(input_buf) > 0) {
            config->duration_seconds = (uint32_t)atoi(input_buf);
        }
    }
    if (config->duration_seconds == 0) {
        printf("  ✓ Unlimited duration (press Ctrl+C to stop)\n");
    } else {
        printf("  ✓ Will capture for %u seconds\n", config->duration_seconds);
    }

    // 5. Promiscuous mode
    printf("\n  Enable promiscuous mode? [Y/n]: ");
    fflush(stdout);
    if (fgets(input_buf, sizeof(input_buf), stdin) != NULL) {
        input_buf[strcspn(input_buf, "\n")] = '\0';
        if (input_buf[0] == 'n' || input_buf[0] == 'N') {
            config->promiscuous = 0;
            printf("  ✓ Promiscuous mode: OFF\n");
        } else {
            config->promiscuous = 1;
            printf("  ✓ Promiscuous mode: ON\n");
        }
    }

    // Print summary
    printf("\n  ┌─────────────────────────────────────────────────────────┐\n");
    printf("  │              Live Capture Configuration                  │\n");
    printf("  ├─────────────────────────────────────────────────────────┤\n");
    printf("  │  Interface:    %-40s │\n", config->interface_name);
    printf("  │  Filter:       %-40s │\n", 
           strlen(config->bpf_filter) > 0 ? config->bpf_filter : "(none)");
    printf("  │  Max Packets:  %-40u │\n", config->max_packets);
    printf("  │  Duration:     %-37u sec│\n", config->duration_seconds);
    printf("  │  Promiscuous:  %-40s │\n", config->promiscuous ? "YES" : "NO");
    printf("  │  Snap Length:  %-37d B  │\n", config->snap_length);
    printf("  │  IDS Workers:  %-40u │\n", config->ids_workers);
    printf("  │  MQTT Workers: %-40u │\n", config->mqtt_workers);
    printf("  │  Queue Size:   %-40u │\n", config->pipeline_queue_capacity);
    printf("  └─────────────────────────────────────────────────────────┘\n\n");

    printf("  [Pipeline Tuning] Override with env vars if needed:\n");
    printf("    IWSN_IDS_WORKERS, IWSN_MQTT_WORKERS, IWSN_PIPELINE_QUEUE_CAPACITY\n\n");

    return 0;
}

/* ========== Initialize Live Capture Context ========== */

live_capture_ctx_t* live_capture_init(live_capture_config_t *config, dpi_engine_t *engine) {
    live_capture_ctx_t *ctx = (live_capture_ctx_t *)calloc(1, sizeof(live_capture_ctx_t));
    if (!ctx) {
        fprintf(stderr, "[Error] Failed to allocate live capture context\n");
        return NULL;
    }

    memcpy(&ctx->config, config, sizeof(live_capture_config_t));
    ctx->dpi_engine = engine;
    ctx->stop_requested = 0;
    ctx->rule_engine = NULL;
    ctx->ids_callback = NULL;
    ctx->ids_is_blocked_callback = NULL;
    ctx->ids_mode = 0;
    ctx->mqtt_context = NULL;
    ctx->mqtt_callback = NULL;
    ctx->mqtt_mode = 0;
    snprintf(ctx->realtime_metrics_file, sizeof(ctx->realtime_metrics_file), "live_realtime_metrics.txt");
    ctx->metrics_flush_interval_packets = 25;

    // Initialize stats
    memset(&ctx->stats, 0, sizeof(live_capture_stats_t));
    ctx->stats.is_running = 0;

    // Initialize pcap_stats for compatibility
    memset(&ctx->pcap_stats, 0, sizeof(pcap_stats_t));
    snprintf(ctx->pcap_stats.filename, sizeof(ctx->pcap_stats.filename),
             "LIVE:%s", config->interface_name);
    ctx->pcap_stats.min_packet_size = 0xFFFFFFFF;

    return ctx;
}

/* ========== Start Live Capture ========== */

int live_capture_start(live_capture_ctx_t *ctx) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;
    time_t deadline = 0;
    live_pipeline_runtime_t pipeline;

    printf("[LIVE CAPTURE] Opening interface: %s\n", ctx->config.interface_name);

    // Open live device
    ctx->handle = pcap_open_live(
        ctx->config.interface_name,
        ctx->config.snap_length,
        ctx->config.promiscuous,
        ctx->config.read_timeout_ms,
        errbuf
    );

    if (!ctx->handle) {
        fprintf(stderr, "[Error] Cannot open interface '%s': %s\n",
                ctx->config.interface_name, errbuf);
        fprintf(stderr, "[Hint]  Try running with sudo: sudo ./bin/<binary> \n");
        return -1;
    }

    // Get and store datalink type
    int datalink = pcap_datalink(ctx->handle);
    printf("[LIVE CAPTURE] Datalink type: %s\n", pcap_datalink_val_to_name(datalink));
    ctx->dpi_engine->datalink_type = datalink;
    ctx->pcap_stats.datalink_type = datalink;

    if (datalink != DLT_EN10MB && datalink != DLT_LINUX_SLL && datalink != DLT_LINUX_SLL2) {
        fprintf(stderr, "[Error] Unsupported datalink type: %s\n",
                pcap_datalink_val_to_name(datalink));
        pcap_close(ctx->handle);
        ctx->handle = NULL;
        return -1;
    }

    // Apply BPF filter if set
    if (strlen(ctx->config.bpf_filter) > 0) {
        struct bpf_program fp;
        if (pcap_compile(ctx->handle, &fp, ctx->config.bpf_filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "[Error] Invalid BPF filter '%s': %s\n",
                    ctx->config.bpf_filter, pcap_geterr(ctx->handle));
            pcap_close(ctx->handle);
            ctx->handle = NULL;
            return -1;
        }
        if (pcap_setfilter(ctx->handle, &fp) == -1) {
            fprintf(stderr, "[Error] Failed to apply BPF filter: %s\n",
                    pcap_geterr(ctx->handle));
            pcap_freecode(&fp);
            pcap_close(ctx->handle);
            ctx->handle = NULL;
            return -1;
        }
        pcap_freecode(&fp);
        printf("[LIVE CAPTURE] BPF filter applied: %s\n", ctx->config.bpf_filter);
    }

    // Install signal handler for graceful Ctrl+C
    g_live_capture_stop = 0;
    struct sigaction sa;
    sa.sa_handler = live_capture_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    // Calculate deadline if duration is set
    if (ctx->config.duration_seconds > 0) {
        deadline = time(NULL) + ctx->config.duration_seconds;
    }

    gettimeofday(&ctx->stats.capture_start, NULL);
    ctx->pcap_stats.start_time = ctx->stats.capture_start;
    ctx->stats.is_running = 1;

    if (live_pipeline_start(ctx, &pipeline) != 0) {
        fprintf(stderr, "[Error] Failed to start multithreaded live pipeline\n");
        pcap_close(ctx->handle);
        ctx->handle = NULL;
        signal(SIGINT, SIG_DFL);
        return -1;
    }

        printf("[LIVE CAPTURE] Capture started. Press Ctrl+C to stop.\n");
        printf("[LIVE CAPTURE] Threaded pipeline enabled: IDS workers=%u, MQTT workers=%u, queue/shard=%u\n",
            pipeline.ids_worker_count,
            pipeline.mqtt_worker_count,
            ctx->config.pipeline_queue_capacity);
    printf("─────────────────────────────────────────────────────────────\n");
    printf("  %-10s %-18s %-18s %-8s %-8s %-16s\n",
           "Packet#", "Source IP", "Dest IP", "Proto", "Size", "L7 Protocol");
    printf("─────────────────────────────────────────────────────────────\n");

    /* ===== Main Capture Loop ===== */
    time_t last_snapshot_write_time = 0;
    while (!g_live_capture_stop) {
        time_t now_loop = time(NULL);
        if (now_loop - last_snapshot_write_time >= 5) {
            live_capture_write_metrics_snapshot(ctx);
            last_snapshot_write_time = now_loop;
        }

        // Check duration limit
        if (deadline > 0 && time(NULL) >= deadline) {
            printf("\n[LIVE CAPTURE] Duration limit reached (%u seconds).\n",
                   ctx->config.duration_seconds);
            break;
        }

        // Check packet count limit
        if (ctx->config.max_packets > 0 &&
            ctx->stats.packets_captured >= ctx->config.max_packets) {
            printf("\n[LIVE CAPTURE] Packet limit reached (%u packets).\n",
                   ctx->config.max_packets);
            break;
        }

        res = pcap_next_ex(ctx->handle, &header, &packet);

        if (res == 0) {
            continue;  // Timeout, no packet — loop again
        }
        if (res < 0) {
            if (g_live_capture_stop) break;  // Interrupted
            fprintf(stderr, "[Error] pcap_next_ex: %s\n", pcap_geterr(ctx->handle));
            break;
        }

        /* --- Process the packet through the DPI engine --- */
        ctx->stats.packets_captured++;
        ctx->stats.bytes_captured += header->caplen;

        // Track timing
        if (ctx->stats.packets_captured == 1) {
            ctx->pcap_stats.start_time = header->ts;
        }
        ctx->pcap_stats.end_time = header->ts;

        // Update pcap_stats for ALL packets (including non-IP)
        ctx->pcap_stats.total_bytes += header->caplen;
        if (header->caplen < ctx->pcap_stats.min_packet_size) {
            ctx->pcap_stats.min_packet_size = header->caplen;
        }
        if (header->caplen > ctx->pcap_stats.max_packet_size) {
            ctx->pcap_stats.max_packet_size = header->caplen;
        }

        // Parse packet through DPI engine
        parsed_packet_t parsed;
        if (parse_packet(ctx->dpi_engine, packet, header->caplen, header->ts, &parsed) == 0) {
            parsed.packet_number = (uint32_t)ctx->stats.packets_captured;

            // IDS mode: analyze packet for attacks in real-time via callback
            if (ctx->ids_mode || ctx->mqtt_mode) {
                uint32_t ids_index;
                int needs_raw_copy;
                live_packet_task_t *task;

                needs_raw_copy = live_packet_is_mqtt_candidate(&parsed);
                task = live_packet_task_create(&parsed, needs_raw_copy);
                if (!task) {
                    live_counter_inc_u64(&pipeline.ids_queue_drops);
                } else {
                    ids_index = task->flow_hash % pipeline.ids_worker_count;
                    if (live_packet_queue_push_nowait(&pipeline.ids_queues[ids_index], task) != 0) {
                        live_counter_inc_u64(&pipeline.ids_queue_drops);
                        live_packet_task_destroy(task);
                    } else {
                        uint32_t qsize = live_packet_queue_size(&pipeline.ids_queues[ids_index]);
                        live_counter_max_u64(&pipeline.ids_queue_high_watermark, qsize);
                    }
                }
            }

            // Store packet in flow
            if (parsed.flow) {
                store_packet_in_flow(parsed.flow, &parsed);
            }

            // Track IP-specific stats
            ctx->pcap_stats.ip_packets++;
            ctx->pcap_stats.ip_bytes += header->caplen;

            // Real-time output: print every packet summary
            char src_ip_str[20], dst_ip_str[20];
            snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
                     (parsed.layer3.src_ip >> 24) & 0xFF,
                     (parsed.layer3.src_ip >> 16) & 0xFF,
                     (parsed.layer3.src_ip >> 8) & 0xFF,
                     parsed.layer3.src_ip & 0xFF);
            snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
                     (parsed.layer3.dst_ip >> 24) & 0xFF,
                     (parsed.layer3.dst_ip >> 16) & 0xFF,
                     (parsed.layer3.dst_ip >> 8) & 0xFF,
                     parsed.layer3.dst_ip & 0xFF);

            printf("  %-10lu %-18s %-18s %-8s %-8u %-16s\n",
                   ctx->stats.packets_captured,
                   src_ip_str, dst_ip_str,
                   get_protocol_name(parsed.layer3.protocol),
                   header->caplen,
                   parsed.detected_protocol);

            // Periodic real-time stats (every 100 packets)
            if (ctx->stats.packets_captured % 100 == 0) {
                live_capture_print_realtime_stats(ctx);
            }

            if (ctx->metrics_flush_interval_packets > 0 &&
                (ctx->stats.packets_captured % ctx->metrics_flush_interval_packets == 0)) {
                live_capture_write_metrics_snapshot(ctx);
            }
        } else {
            // Non-IP packet (ARP, LLDP, etc.)
            ctx->pcap_stats.non_ip_packets++;

            if (ctx->metrics_flush_interval_packets > 0 &&
                (ctx->stats.packets_captured % ctx->metrics_flush_interval_packets == 0)) {
                live_capture_write_metrics_snapshot(ctx);
            }
        }
    }

    /* ===== Capture finished ===== */
    gettimeofday(&ctx->stats.capture_end, NULL);
    ctx->stats.is_running = 0;

    uint32_t ids_depth_at_stop = live_pipeline_total_queue_depth(&pipeline, LIVE_TASK_STAGE_IDS);
    uint32_t mqtt_depth_at_stop = live_pipeline_total_queue_depth(&pipeline, LIVE_TASK_STAGE_MQTT);
    live_pipeline_stop(&pipeline);
    if (pipeline.ids_queue_drops > 0 || pipeline.mqtt_queue_drops > 0) {
         printf("[LIVE CAPTURE] Queue drops: IDS=%lu MQTT=%lu\n",
               pipeline.ids_queue_drops,
               pipeline.mqtt_queue_drops);
    }
        printf("[LIVE CAPTURE] Pipeline processed: IDS=%lu MQTT=%lu\n",
            pipeline.ids_processed,
            pipeline.mqtt_processed);
        printf("[LIVE CAPTURE] Queue high watermark: IDS=%lu MQTT=%lu\n",
            pipeline.ids_queue_high_watermark,
            pipeline.mqtt_queue_high_watermark);
        printf("[LIVE CAPTURE] Queue depth at shutdown: IDS=%u MQTT=%u\n",
                ids_depth_at_stop,
                mqtt_depth_at_stop);

    // Get kernel drop stats
    struct pcap_stat ps;
    if (pcap_stats(ctx->handle, &ps) == 0) {
        ctx->stats.packets_dropped = ps.ps_drop;
        ctx->stats.packets_if_dropped = ps.ps_ifdrop;
    }

    // Calculate elapsed time
    ctx->stats.elapsed_seconds =
        (ctx->stats.capture_end.tv_sec - ctx->stats.capture_start.tv_sec) +
        (ctx->stats.capture_end.tv_usec - ctx->stats.capture_start.tv_usec) / 1000000.0;

    if (ctx->stats.elapsed_seconds > 0) {
        ctx->stats.packets_per_second =
            ctx->stats.packets_captured / ctx->stats.elapsed_seconds;
        ctx->stats.megabits_per_second =
            (ctx->stats.bytes_captured * 8.0) / (ctx->stats.elapsed_seconds * 1000000.0);
    }

    // Fill the pcap_stats_t for downstream reporting
    live_capture_fill_pcap_stats(ctx, &ctx->pcap_stats);

    // Flush final snapshot for watch-based Grafana exporters
    live_capture_write_metrics_snapshot(ctx);

    pcap_close(ctx->handle);
    ctx->handle = NULL;

    // Restore default signal handler
    signal(SIGINT, SIG_DFL);

    return 0;
}

/* ========== Stop Live Capture ========== */

void live_capture_stop(live_capture_ctx_t *ctx) {
    if (ctx) {
        ctx->stop_requested = 1;
        g_live_capture_stop = 1;
        if (ctx->handle) {
            pcap_breakloop(ctx->handle);
        }
    }
}

/* ========== Destroy Live Capture Context ========== */

void live_capture_destroy(live_capture_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->handle) {
        pcap_close(ctx->handle);
        ctx->handle = NULL;
    }
    free(ctx);
}

/* ========== Real-time Statistics Display ========== */

void live_capture_print_realtime_stats(const live_capture_ctx_t *ctx) {
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - ctx->stats.capture_start.tv_sec) +
                     (now.tv_usec - ctx->stats.capture_start.tv_usec) / 1000000.0;

    double pps = (elapsed > 0) ? ctx->stats.packets_captured / elapsed : 0;
    double mbps = (elapsed > 0) ? (ctx->stats.bytes_captured * 8.0) / (elapsed * 1000000.0) : 0;

    printf("  ── [STATS] %lu pkts | %lu bytes | %.1f pps | %.3f Mbps | %u flows | %.1fs elapsed ──\n",
           ctx->stats.packets_captured,
           ctx->stats.bytes_captured,
           pps, mbps,
           ctx->dpi_engine->flow_count,
           elapsed);
}

/* ========== Final Capture Summary ========== */

void live_capture_print_summary(const live_capture_ctx_t *ctx) {
    printf("\n\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ║\n");
    printf("║              LIVE CAPTURE SUMMARY                              ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("[CAPTURE INFORMATION]\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Interface:       %s\n", ctx->config.interface_name);
    printf("  BPF Filter:      %s\n",
           strlen(ctx->config.bpf_filter) > 0 ? ctx->config.bpf_filter : "(none)");
    printf("  Promiscuous:     %s\n", ctx->config.promiscuous ? "YES" : "NO");
    printf("\n[CAPTURE STATISTICS]\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Packets Captured:    %lu\n", ctx->stats.packets_captured);
    printf("  Bytes Captured:      %lu (%.2f KB, %.2f MB)\n",
           ctx->stats.bytes_captured,
           ctx->stats.bytes_captured / 1024.0,
           ctx->stats.bytes_captured / (1024.0 * 1024.0));
    printf("  Packets Dropped:     %lu (kernel)\n", ctx->stats.packets_dropped);
    printf("  Packets IF Dropped:  %lu (interface)\n", ctx->stats.packets_if_dropped);
    printf("  Duration:            %.3f seconds\n", ctx->stats.elapsed_seconds);
    printf("  Packet Rate:         %.2f packets/sec\n", ctx->stats.packets_per_second);
    printf("  Throughput:          %.3f Mbps\n", ctx->stats.megabits_per_second);
    printf("\n[DPI ENGINE STATISTICS]\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Total Packets:       %lu\n", ctx->dpi_engine->total_packets);
    printf("  Total Bytes:         %lu\n", ctx->dpi_engine->total_bytes);
    printf("  L2 Parsed:           %lu\n", ctx->dpi_engine->l2_parsed);
    printf("  L3 Parsed:           %lu\n", ctx->dpi_engine->l3_parsed);
    printf("  L4 Parsed:           %lu\n", ctx->dpi_engine->l4_parsed);
    printf("  Flows Created:       %lu\n", ctx->dpi_engine->flows_created);
    printf("  Active Flows:        %u\n", ctx->dpi_engine->flow_count);
    printf("═══════════════════════════════════════════════════════════════\n\n");
}

/* ========== Fill pcap_stats_t from Live Capture ========== */

void live_capture_fill_pcap_stats(live_capture_ctx_t *ctx, pcap_stats_t *stats) {
    snprintf(stats->filename, sizeof(stats->filename), "LIVE:%s", ctx->config.interface_name);
    stats->file_size = ctx->stats.bytes_captured;
    stats->total_packets = (uint32_t)ctx->stats.packets_captured;
    stats->ip_packets = ctx->pcap_stats.ip_packets;
    stats->non_ip_packets = ctx->pcap_stats.non_ip_packets;
    stats->total_flows = ctx->dpi_engine->flow_count;
    stats->total_bytes = ctx->pcap_stats.total_bytes;
    stats->ip_bytes = ctx->pcap_stats.ip_bytes;
    stats->start_time = ctx->pcap_stats.start_time;
    stats->end_time = ctx->pcap_stats.end_time;
    stats->duration_seconds = ctx->stats.elapsed_seconds;
    if (ctx->pcap_stats.min_packet_size == 0xFFFFFFFF) {
        stats->min_packet_size = 0;
    } else {
        stats->min_packet_size = ctx->pcap_stats.min_packet_size;
    }
    stats->max_packet_size = ctx->pcap_stats.max_packet_size;
    if (stats->total_packets > 0) {
        stats->avg_packet_size = (double)stats->total_bytes / stats->total_packets;
    }
    stats->datalink_type = ctx->pcap_stats.datalink_type;
}
