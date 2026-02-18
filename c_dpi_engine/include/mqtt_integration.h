/*
 * MQTT Integration Header
 * Functions to parse MQTT packets after security filtering
 */

#ifndef MQTT_INTEGRATION_H
#define MQTT_INTEGRATION_H

#include "dpi_engine.h"
#include "mqtt_parser.h"

/* ========== MQTT Post-Processing Functions ========== */

// Parse MQTT packet AFTER attack detection (for clean packets only)
int parse_mqtt_packet_secure(parsed_packet_t *parsed);

// Print MQTT statistics summary
void print_mqtt_statistics(void);

#endif /* MQTT_INTEGRATION_H */
