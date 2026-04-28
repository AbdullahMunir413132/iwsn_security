/*
 * IWSN Security - Live Capture Module Header
 * Real-time packet capture and analysis using libpcap
 * Supports interface selection, BPF filters, and duration/count limits
 */

#ifndef LIVE_CAPTURE_H
#define LIVE_CAPTURE_H

#include <stdint.h>
#include <pcap.h>
#include <signal.h>
#include "dpi_engine.h"

/* ========== Capture Mode ========== */
typedef enum {
    CAPTURE_MODE_PCAP = 0,   // Offline PCAP file analysis
    CAPTURE_MODE_LIVE  = 1    // Real-time live capture
} capture_mode_t;

/* ========== Live Capture Configuration ========== */
typedef struct {
    char interface_name[64];      // Network interface (e.g., eth0, wlan0)
    char bpf_filter[512];         // BPF filter expression (optional)
    uint32_t max_packets;         // Max packets to capture (0 = unlimited)
    uint32_t duration_seconds;    // Max capture duration in seconds (0 = unlimited)
    int promiscuous;              // 1 = promiscuous mode, 0 = normal
    int snap_length;              // Snap length (0 = default 65535)
    int read_timeout_ms;          // Read timeout in milliseconds
    uint32_t pipeline_queue_capacity; // Per-shard queue capacity for threaded pipeline
    uint32_t ids_workers;         // IDS worker count (phase 2)
    uint32_t mqtt_workers;        // MQTT worker count (phase 2)
} live_capture_config_t;

/* ========== Live Capture Statistics (real-time) ========== */
typedef struct {
    uint64_t packets_captured;
    uint64_t bytes_captured;
    uint64_t packets_dropped;       // Packets dropped by kernel
    uint64_t packets_if_dropped;    // Packets dropped by interface
    struct timeval capture_start;
    struct timeval capture_end;
    double elapsed_seconds;
    double packets_per_second;
    double megabits_per_second;
    int is_running;
} live_capture_stats_t;

/* ========== IDS callback function pointer type ========== */
/* This avoids a hard dependency on rule_engine.h for DPI-only builds */
typedef void (*ids_packet_callback_t)(void *rule_engine, const parsed_packet_t *packet);
typedef void (*mqtt_packet_callback_t)(void *mqtt_context, parsed_packet_t *packet);
typedef int (*ids_is_blocked_callback_t)(void *rule_engine, uint32_t ip_address);

/* ========== Live Capture Context ========== */
typedef struct {
    pcap_t *handle;
    live_capture_config_t config;
    live_capture_stats_t stats;
    dpi_engine_t *dpi_engine;
    pcap_stats_t pcap_stats;       // Reuse the existing pcap_stats_t for compatibility

    // Optional IDS integration via callback
    void *rule_engine;                  // Opaque pointer to rule_engine_t
    ids_packet_callback_t ids_callback; // Function to call for per-packet IDS analysis
    ids_is_blocked_callback_t ids_is_blocked_callback; // Optional callback for blocklist checks
    int ids_mode;                       // 1 if IDS callback is set

    // Optional MQTT integration via callback
    void *mqtt_context;                    // Opaque pointer for MQTT callback context
    mqtt_packet_callback_t mqtt_callback;  // Function to call for per-packet MQTT parsing
    int mqtt_mode;                         // 1 if MQTT callback is set

    // Real-time metrics snapshot settings (for Grafana push watchers)
    char realtime_metrics_file[256];
    uint32_t metrics_flush_interval_packets;

    // Signal handling for graceful stop
    volatile int stop_requested;
} live_capture_ctx_t;

/* ========== Function Prototypes ========== */

// Mode selection: prompt user for PCAP or Live mode
capture_mode_t prompt_capture_mode(void);

// Interface management
int list_network_interfaces(void);
int select_network_interface(char *iface_name, size_t name_len);

// Configuration
void live_capture_config_defaults(live_capture_config_t *config);
int prompt_live_capture_config(live_capture_config_t *config);

// Live capture operations
live_capture_ctx_t* live_capture_init(live_capture_config_t *config, dpi_engine_t *engine);
int live_capture_start(live_capture_ctx_t *ctx);
void live_capture_stop(live_capture_ctx_t *ctx);
void live_capture_destroy(live_capture_ctx_t *ctx);

// Real-time statistics display
void live_capture_print_realtime_stats(const live_capture_ctx_t *ctx);
void live_capture_print_summary(const live_capture_ctx_t *ctx);

// Populate pcap_stats_t from live capture (for compatibility with existing reporting)
void live_capture_fill_pcap_stats(live_capture_ctx_t *ctx, pcap_stats_t *stats);

// Global stop flag for signal handler
extern volatile sig_atomic_t g_live_capture_stop;
void live_capture_signal_handler(int signum);

#endif /* LIVE_CAPTURE_H */
