/*
 * Detailed Report Generator Header
 */

#ifndef DETAILED_REPORTS_H
#define DETAILED_REPORTS_H

#include "dpi_engine.h"

// Generate comprehensive DPI detailed report (includes flows and packets)
void generate_dpi_detailed_report(dpi_engine_t *engine, pcap_stats_t *pcap_stats, const char *output_file);

#endif
