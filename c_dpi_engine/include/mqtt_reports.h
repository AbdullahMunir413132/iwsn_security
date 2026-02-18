/*
 * MQTT Report Generator Header
 */

#ifndef MQTT_REPORTS_H
#define MQTT_REPORTS_H

#include "dpi_engine.h"

// Generate detailed MQTT packet report with payloads
void generate_mqtt_report(dpi_engine_t *engine, const char *output_file);

#endif
