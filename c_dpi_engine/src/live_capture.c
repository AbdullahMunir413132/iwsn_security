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
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <time.h>
#include "live_capture.h"
#include "dpi_engine.h"

/* ========== Global Stop Flag for Signal Handler ========== */
volatile sig_atomic_t g_live_capture_stop = 0;

void live_capture_signal_handler(int signum) {
    (void)signum;
    g_live_capture_stop = 1;
    printf("\n\n[LIVE CAPTURE] Ctrl+C received — stopping capture gracefully...\n");
}

/* ========== Mode Selection Prompt ========== */

capture_mode_t prompt_capture_mode(void) {
    int choice = 0;

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
    config->bpf_filter[0] = '\0';
}

/* ========== Interactive Configuration Prompt ========== */

int prompt_live_capture_config(live_capture_config_t *config) {
    char input_buf[512];

    live_capture_config_defaults(config);

    // 1. Select interface
    if (select_network_interface(config->interface_name, sizeof(config->interface_name)) != 0) {
        return -1;
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
    printf("  └─────────────────────────────────────────────────────────┘\n\n");

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
    ctx->ids_mode = 0;

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

    printf("[LIVE CAPTURE] Capture started. Press Ctrl+C to stop.\n");
    printf("─────────────────────────────────────────────────────────────\n");
    printf("  %-10s %-18s %-18s %-8s %-8s %-16s\n",
           "Packet#", "Source IP", "Dest IP", "Proto", "Size", "L7 Protocol");
    printf("─────────────────────────────────────────────────────────────\n");

    /* ===== Main Capture Loop ===== */
    while (!g_live_capture_stop) {
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
            if (ctx->ids_mode && ctx->ids_callback && ctx->rule_engine) {
                ctx->ids_callback(ctx->rule_engine, &parsed);
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
        } else {
            // Non-IP packet (ARP, LLDP, etc.)
            ctx->pcap_stats.non_ip_packets++;
        }
    }

    /* ===== Capture finished ===== */
    gettimeofday(&ctx->stats.capture_end, NULL);
    ctx->stats.is_running = 0;

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
