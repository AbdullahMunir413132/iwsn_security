/*
 * IDS (Rule Engine) Detailed Report Generator Header
 */

#ifndef IDS_REPORTS_H
#define IDS_REPORTS_H

#include "rule_engine.h"
#include "dpi_engine.h"

// Generate comprehensive IDS/Rule Engine detailed report
void generate_ids_report(rule_engine_t *engine, dpi_engine_t *dpi_engine, const char *output_file);

#endif
