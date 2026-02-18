# MQTT Parser Module

## Overview
The MQTT Parser is a specialized protocol decoder designed for deep inspection of MQTT (Message Queuing Telemetry Transport) packets in IoT networks. It provides complete parsing of MQTT v3.1 and v3.1.1 packets, including anomaly detection for security analysis.

## Technical Architecture

### Core Components

#### 1. **MQTT Packet Structure** (`mqtt_packet_t`)
```c
typedef struct {
    // Fixed header fields
    uint8_t packet_type;                     // 1-14 (CONNECT, PUBLISH, etc.)
    uint8_t qos;                             // Quality of Service (0, 1, 2)
    uint8_t retain;                          // Retain flag
    uint8_t dup;                             // Duplicate flag
    uint32_t remaining_length;               // Variable length encoding
    uint16_t packet_id;                      // For QoS > 0
    
    // CONNECT packet fields
    char protocol_name[32];                  // "MQTT" or "MQIsdp"
    uint8_t protocol_version;                // 3 (v3.1) or 4 (v3.1.1)
    uint8_t connect_flags;                   // Username, Password, Will, etc.
    uint16_t keep_alive;                     // Keep alive timer in seconds
    char client_id[256];                     // Unique client identifier
    char username[256];                      // Optional authentication
    char password[256];                      // Optional authentication
    char will_topic[256];                    // Last will topic
    char will_message[512];                  // Last will message
    
    // PUBLISH packet fields
    char topic[256];                         // Publication topic
    uint8_t *payload;                        // Message payload (dynamic)
    uint32_t payload_length;                 // Payload size in bytes
    
    // SUBSCRIBE packet fields
    char subscribe_topics[10][256];          // Up to 10 topics
    uint8_t subscribe_qos[10];               // QoS for each topic
    uint8_t subscribe_count;                 // Number of topics
    
    // Parsing status
    uint8_t is_valid;                        // Parse success flag
    char error_message[256];                 // Error description
    
} mqtt_packet_t;
```

#### 2. **MQTT Statistics** (`mqtt_statistics_t`)
```c
typedef struct {
    // Packet type counters
    uint64_t total_packets;
    uint64_t connect_count;
    uint64_t connack_count;
    uint64_t publish_count;
    uint64_t subscribe_count;
    uint64_t unsubscribe_count;
    uint64_t pingreq_count;
    uint64_t pingresp_count;
    uint64_t disconnect_count;
    uint64_t invalid_count;
    
    // Anomaly detection
    uint64_t malformed_packets;              // Parse failures
    uint64_t oversized_packets;              // Excessive payload size
    uint64_t suspicious_topics;              // Injection patterns
    
} mqtt_statistics_t;
```

## MQTT Protocol Overview

### Packet Types (Control Packets)
```c
#define MQTT_CONNECT      1   // Client request to connect to server
#define MQTT_CONNACK      2   // Connect acknowledgment
#define MQTT_PUBLISH      3   // Publish message
#define MQTT_PUBACK       4   // Publish acknowledgment (QoS 1)
#define MQTT_PUBREC       5   // Publish received (QoS 2, part 1)
#define MQTT_PUBREL       6   // Publish release (QoS 2, part 2)
#define MQTT_PUBCOMP      7   // Publish complete (QoS 2, part 3)
#define MQTT_SUBSCRIBE    8   // Client subscribe request
#define MQTT_SUBACK       9   // Subscribe acknowledgment
#define MQTT_UNSUBSCRIBE  10  // Unsubscribe request
#define MQTT_UNSUBACK     11  // Unsubscribe acknowledgment
#define MQTT_PINGREQ      12  // PING request
#define MQTT_PINGRESP     13  // PING response
#define MQTT_DISCONNECT   14  // Client disconnect
```

### Quality of Service (QoS) Levels
- **QoS 0**: At most once (fire and forget)
- **QoS 1**: At least once (acknowledged delivery)
- **QoS 2**: Exactly once (four-step handshake)

## Packet Parsing

### Main Parser Entry Point:
```c
int mqtt_parse_packet(const uint8_t *data, uint32_t data_len, 
                     mqtt_packet_t *packet) {
    memset(packet, 0, sizeof(mqtt_packet_t));
    
    if (data_len < 2) {
        strcpy(packet->error_message, "Packet too short");
        return -1;
    }
    
    // Parse fixed header
    uint8_t fixed_header = data[0];
    packet->packet_type = (fixed_header >> 4) & 0x0F;
    packet->dup = (fixed_header >> 3) & 0x01;
    packet->qos = (fixed_header >> 1) & 0x03;
    packet->retain = fixed_header & 0x01;
    
    // Decode remaining length (variable length encoding)
    uint32_t bytes_consumed;
    if (decode_remaining_length(&data[1], data_len - 1, 
                               &packet->remaining_length, 
                               &bytes_consumed) < 0) {
        strcpy(packet->error_message, "Invalid remaining length encoding");
        return -1;
    }
    
    // Calculate payload offset
    uint32_t payload_offset = 1 + bytes_consumed;
    
    if (payload_offset + packet->remaining_length > data_len) {
        strcpy(packet->error_message, "Incomplete packet");
        return -1;
    }
    
    // Parse variable header and payload based on packet type
    const uint8_t *payload = &data[payload_offset];
    uint32_t payload_len = packet->remaining_length;
    
    int parse_result = 0;
    switch (packet->packet_type) {
        case MQTT_CONNECT:
            parse_result = parse_connect_packet(payload, payload_len, packet);
            break;
        case MQTT_PUBLISH:
            parse_result = parse_publish_packet(payload, payload_len, packet);
            break;
        case MQTT_SUBSCRIBE:
            parse_result = parse_subscribe_packet(payload, payload_len, packet);
            break;
        // ... other packet types
    }
    
    if (parse_result < 0) {
        return -1;
    }
    
    packet->is_valid = 1;
    global_mqtt_stats.total_packets++;
    
    return 0;
}
```

### Variable Length Encoding:
MQTT uses a variable length encoding for the "remaining length" field:

```c
static int decode_remaining_length(const uint8_t *data, uint32_t data_len, 
                                   uint32_t *remaining_len, 
                                   uint32_t *bytes_consumed) {
    uint32_t multiplier = 1;
    uint32_t value = 0;
    uint32_t pos = 0;
    uint8_t encoded_byte;
    
    do {
        if (pos >= data_len || pos >= 4) {
            return -1;  // Invalid: max 4 bytes
        }
        
        encoded_byte = data[pos];
        value += (encoded_byte & 127) * multiplier;
        multiplier *= 128;
        pos++;
        
        if (multiplier > 128*128*128) {
            return -1;  // Malformed
        }
    } while ((encoded_byte & 128) != 0);  // Continue while MSB is set
    
    *remaining_len = value;
    *bytes_consumed = pos;
    return 0;
}
```

**How it works:**
- Each byte encodes 7 bits of data
- MSB (bit 7) indicates continuation (0 = last byte, 1 = more bytes follow)
- Maximum: 4 bytes → 268,435,455 bytes (256 MB)
- Examples:
  - `0x00` → 0
  - `0x7F` → 127
  - `0x80 0x01` → 128
  - `0xFF 0x7F` → 16,383

### UTF-8 String Parsing:
MQTT strings are length-prefixed UTF-8:

```c
static int read_mqtt_string(const uint8_t *data, uint32_t data_len, 
                            uint32_t *pos, char *output, size_t output_len) {
    // Check for length prefix (2 bytes, big-endian)
    if (*pos + 2 > data_len) {
        return -1;
    }
    
    uint16_t str_len = (data[*pos] << 8) | data[*pos + 1];
    *pos += 2;
    
    // Validate string length
    if (*pos + str_len > data_len || str_len >= output_len) {
        return -1;
    }
    
    // Copy string data
    memcpy(output, &data[*pos], str_len);
    output[str_len] = '\0';  // Null terminate
    *pos += str_len;
    
    return 0;
}
```

**Format:**
```
+--------+--------+------------------+
| MSB    | LSB    | String Data      |
| Length | Length | (UTF-8 encoded)  |
+--------+--------+------------------+
  2 bytes          N bytes
```

## Packet Type Parsers

### 1. CONNECT Packet Parser

```c
static int parse_connect_packet(const uint8_t *payload, uint32_t payload_len, 
                               mqtt_packet_t *packet) {
    uint32_t pos = 0;
    
    // Read protocol name (e.g., "MQTT")
    if (read_mqtt_string(payload, payload_len, &pos, 
                        packet->protocol_name, 
                        sizeof(packet->protocol_name)) < 0) {
        strcpy(packet->error_message, "Failed to read protocol name");
        return -1;
    }
    
    // Read protocol version (3 = v3.1, 4 = v3.1.1)
    if (pos >= payload_len) return -1;
    packet->protocol_version = payload[pos++];
    
    // Read connect flags byte
    //   Bit 7: Username Flag
    //   Bit 6: Password Flag
    //   Bit 5: Will Retain
    //   Bit 4-3: Will QoS
    //   Bit 2: Will Flag
    //   Bit 1: Clean Session
    //   Bit 0: Reserved (must be 0)
    if (pos >= payload_len) return -1;
    packet->connect_flags = payload[pos++];
    
    // Read keep alive timer (big-endian 16-bit)
    if (pos + 2 > payload_len) return -1;
    packet->keep_alive = (payload[pos] << 8) | payload[pos + 1];
    pos += 2;
    
    // Read client ID (required)
    if (read_mqtt_string(payload, payload_len, &pos, 
                        packet->client_id, 
                        sizeof(packet->client_id)) < 0) {
        strcpy(packet->error_message, "Failed to read client ID");
        return -1;
    }
    
    // Read Will Topic and Message (if Will Flag is set)
    if (packet->connect_flags & 0x04) {  // Will Flag
        if (read_mqtt_string(payload, payload_len, &pos, 
                            packet->will_topic, 
                            sizeof(packet->will_topic)) < 0) {
            strcpy(packet->error_message, "Failed to read will topic");
            return -1;
        }
        if (read_mqtt_string(payload, payload_len, &pos, 
                            packet->will_message, 
                            sizeof(packet->will_message)) < 0) {
            strcpy(packet->error_message, "Failed to read will message");
            return -1;
        }
    }
    
    // Read Username (if Username Flag is set)
    if (packet->connect_flags & 0x80) {
        if (read_mqtt_string(payload, payload_len, &pos, 
                            packet->username, 
                            sizeof(packet->username)) < 0) {
            strcpy(packet->error_message, "Failed to read username");
            return -1;
        }
    }
    
    // Read Password (if Password Flag is set)
    if (packet->connect_flags & 0x40) {
        if (read_mqtt_string(payload, payload_len, &pos, 
                            packet->password, 
                            sizeof(packet->password)) < 0) {
            strcpy(packet->error_message, "Failed to read password");
            return -1;
        }
    }
    
    global_mqtt_stats.connect_count++;
    return 0;
}
```

**CONNECT Packet Structure:**
```
+------------------+
| Fixed Header     | (Type=1, Flags, Remaining Length)
+------------------+
| Protocol Name    | ("MQTT" for v3.1.1, "MQIsdp" for v3.1)
+------------------+
| Protocol Version | (4 for v3.1.1, 3 for v3.1)
+------------------+
| Connect Flags    | (Username, Password, Will, Clean Session)
+------------------+
| Keep Alive       | (16-bit timer in seconds)
+------------------+
| Client ID        | (UTF-8 string)
+------------------+
| Will Topic       | (if Will Flag set)
+------------------+
| Will Message     | (if Will Flag set)
+------------------+
| Username         | (if Username Flag set)
+------------------+
| Password         | (if Password Flag set)
+------------------+
```

### 2. PUBLISH Packet Parser

```c
static int parse_publish_packet(const uint8_t *payload, uint32_t payload_len, 
                               mqtt_packet_t *packet) {
    uint32_t pos = 0;
    
    // Read topic name
    if (read_mqtt_string(payload, payload_len, &pos, 
                        packet->topic, 
                        sizeof(packet->topic)) < 0) {
        strcpy(packet->error_message, "Failed to read topic");
        return -1;
    }
    
    // Read packet ID (only present if QoS > 0)
    if (packet->qos > 0) {
        if (pos + 2 > payload_len) return -1;
        packet->packet_id = (payload[pos] << 8) | payload[pos + 1];
        pos += 2;
    }
    
    // Read payload (rest of packet)
    packet->payload_length = payload_len - pos;
    if (packet->payload_length > 0) {
        // Dynamically allocate payload buffer
        packet->payload = (uint8_t*)malloc(packet->payload_length + 1);
        if (packet->payload) {
            memcpy(packet->payload, &payload[pos], packet->payload_length);
            packet->payload[packet->payload_length] = '\0';  // Null terminate
        }
    }
    
    global_mqtt_stats.publish_count++;
    return 0;
}
```

**PUBLISH Packet Structure:**
```
+------------------+
| Fixed Header     | (Type=3, DUP, QoS, RETAIN, Remaining Length)
+------------------+
| Topic Name       | (UTF-8 string)
+------------------+
| Packet ID        | (16-bit, only if QoS > 0)
+------------------+
| Payload          | (Application message, arbitrary bytes)
+------------------+
```

### 3. SUBSCRIBE Packet Parser

```c
static int parse_subscribe_packet(const uint8_t *payload, uint32_t payload_len, 
                                 mqtt_packet_t *packet) {
    uint32_t pos = 0;
    
    // Read packet ID (SUBSCRIBE always has packet ID)
    if (pos + 2 > payload_len) return -1;
    packet->packet_id = (payload[pos] << 8) | payload[pos + 1];
    pos += 2;
    
    // Read topic filters (can have multiple)
    packet->subscribe_count = 0;
    while (pos < payload_len && packet->subscribe_count < 10) {
        // Read topic filter string
        if (read_mqtt_string(payload, payload_len, &pos, 
                            packet->subscribe_topics[packet->subscribe_count], 
                            sizeof(packet->subscribe_topics[0])) < 0) {
            break;
        }
        
        // Read requested QoS (1 byte)
        if (pos >= payload_len) break;
        packet->subscribe_qos[packet->subscribe_count] = payload[pos++] & 0x03;
        
        packet->subscribe_count++;
    }
    
    if (packet->subscribe_count == 0) {
        strcpy(packet->error_message, "No topics in SUBSCRIBE");
        return -1;
    }
    
    global_mqtt_stats.subscribe_count++;
    return 0;
}
```

**SUBSCRIBE Packet Structure:**
```
+------------------+
| Fixed Header     | (Type=8, Flags, Remaining Length)
+------------------+
| Packet ID        | (16-bit)
+------------------+
| Topic Filter 1   | (UTF-8 string with wildcards: +, #)
+------------------+
| Requested QoS 1  | (1 byte: 0, 1, or 2)
+------------------+
| Topic Filter 2   | (optional)
+------------------+
| Requested QoS 2  | (optional)
+------------------+
| ...              |
+------------------+
```

**Topic Wildcards:**
- `+` : Single-level wildcard (e.g., `sensor/+/temperature`)
- `#` : Multi-level wildcard (e.g., `sensor/#` matches all under sensor/)

## Anomaly Detection

### Security Analysis Features:

```c
int mqtt_detect_anomalies(const mqtt_packet_t *packet, 
                         char *anomaly_desc, size_t desc_len) {
    if (!packet || !packet->is_valid) return 0;
    
    // 1. Command Injection Detection
    if (packet->packet_type == MQTT_PUBLISH || 
        packet->packet_type == MQTT_SUBSCRIBE) {
        const char *topic = (packet->packet_type == MQTT_PUBLISH) ? 
                           packet->topic : 
                           packet->subscribe_topics[0];
        
        // Check for injection patterns
        if (strstr(topic, "$(") ||      // Shell command substitution
            strstr(topic, "`") ||        // Backticks
            strstr(topic, "../") ||      // Path traversal
            strstr(topic, "..\\") ||     // Windows path traversal
            strstr(topic, "<script>")) { // XSS
            
            snprintf(anomaly_desc, desc_len, 
                    "Suspicious topic contains injection patterns: %s", topic);
            global_mqtt_stats.suspicious_topics++;
            return 1;
        }
        
        // 2. Excessive Topic Length
        if (strlen(topic) > 200) {
            snprintf(anomaly_desc, desc_len, 
                    "Topic name too long: %zu bytes", strlen(topic));
            global_mqtt_stats.suspicious_topics++;
            return 1;
        }
    }
    
    // 3. Oversized Payload
    if (packet->packet_type == MQTT_PUBLISH && 
        packet->payload_length > 1024*1024) {  // 1 MB
        snprintf(anomaly_desc, desc_len, 
                "PUBLISH payload too large: %u bytes", 
                packet->payload_length);
        global_mqtt_stats.oversized_packets++;
        return 1;
    }
    
    // 4. Suspicious Client ID
    if (packet->packet_type == MQTT_CONNECT) {
        if (strlen(packet->client_id) > 200 || 
            strlen(packet->client_id) == 0) {
            snprintf(anomaly_desc, desc_len, 
                    "Suspicious client ID length: %zu", 
                    strlen(packet->client_id));
            return 1;
        }
    }
    
    return 0;  // No anomalies detected
}
```

**Detected Anomalies:**
1. **Injection Attacks**: Command injection, path traversal, XSS patterns
2. **Length Violations**: Excessive topic/client ID lengths
3. **Oversized Data**: Large payloads that could cause DoS
4. **Malformed Packets**: Invalid encoding or structure

## Traffic Detection

### Identifying MQTT Traffic:

```c
int is_mqtt_traffic(uint16_t src_port, uint16_t dst_port, 
                   const uint8_t *payload, uint32_t payload_len) {
    // 1. Check standard MQTT ports
    if (src_port == 1883 || dst_port == 1883 ||     // MQTT
        src_port == 8883 || dst_port == 8883) {     // MQTT over TLS
        return 1;
    }
    
    // 2. Try to detect MQTT by packet structure
    if (payload && payload_len >= 2) {
        uint8_t packet_type = (payload[0] >> 4) & 0x0F;
        
        // Valid MQTT packet types: 1-14
        if (packet_type >= 1 && packet_type <= 14) {
            // Validate variable length encoding
            uint32_t remaining_len, bytes_consumed;
            if (decode_remaining_length(&payload[1], payload_len - 1, 
                                       &remaining_len, 
                                       &bytes_consumed) == 0) {
                // Reasonable size check
                if (remaining_len > 0 && remaining_len < 256*1024) {
                    return 1;  // Likely MQTT
                }
            }
        }
    }
    
    return 0;  // Not MQTT
}
```

**Detection Methods:**
1. **Port-based**: Standard ports 1883 (unencrypted), 8883 (TLS)
2. **Heuristic**: Valid packet type (1-14) + valid length encoding

## Utility Functions

### Packet Type Names:
```c
const char* mqtt_get_packet_type_name(uint8_t packet_type) {
    switch (packet_type) {
        case MQTT_CONNECT:      return "CONNECT";
        case MQTT_CONNACK:      return "CONNACK";
        case MQTT_PUBLISH:      return "PUBLISH";
        case MQTT_PUBACK:       return "PUBACK";
        case MQTT_PUBREC:       return "PUBREC";
        case MQTT_PUBREL:       return "PUBREL";
        case MQTT_PUBCOMP:      return "PUBCOMP";
        case MQTT_SUBSCRIBE:    return "SUBSCRIBE";
        case MQTT_SUBACK:       return "SUBACK";
        case MQTT_UNSUBSCRIBE:  return "UNSUBSCRIBE";
        case MQTT_UNSUBACK:     return "UNSUBACK";
        case MQTT_PINGREQ:      return "PINGREQ";
        case MQTT_PINGRESP:     return "PINGRESP";
        case MQTT_DISCONNECT:   return "DISCONNECT";
        default:                return "UNKNOWN";
    }
}
```

### Packet Display:
```c
void mqtt_print_packet(const mqtt_packet_t *packet) {
    if (!packet || !packet->is_valid) {
        printf("  [MQTT] Invalid or malformed packet\n");
        return;
    }
    
    printf("  [MQTT] Type: %s", mqtt_get_packet_type_name(packet->packet_type));
    
    // Print flags
    if (packet->qos > 0) printf(" | QoS: %d", packet->qos);
    if (packet->retain) printf(" | RETAIN");
    if (packet->dup) printf(" | DUP");
    printf("\n");
    
    // Type-specific information
    switch (packet->packet_type) {
        case MQTT_CONNECT:
            printf("  [MQTT] Protocol: %s v%d\n", 
                   packet->protocol_name, packet->protocol_version);
            printf("  [MQTT] Client ID: %s\n", packet->client_id);
            printf("  [MQTT] Keep Alive: %d seconds\n", packet->keep_alive);
            if (strlen(packet->username) > 0) {
                printf("  [MQTT] Username: %s\n", packet->username);
            }
            break;
            
        case MQTT_PUBLISH:
            printf("  [MQTT] Topic: %s\n", packet->topic);
            printf("  [MQTT] Payload Length: %u bytes\n", 
                   packet->payload_length);
            
            // Print payload if printable text
            if (packet->payload && packet->payload_length < 200) {
                int is_printable = 1;
                for (uint32_t i = 0; i < packet->payload_length; i++) {
                    if (packet->payload[i] < 32 && 
                        packet->payload[i] != '\n' && 
                        packet->payload[i] != '\r') {
                        is_printable = 0;
                        break;
                    }
                }
                if (is_printable) {
                    printf("  [MQTT] Payload: %.*s\n", 
                           (int)packet->payload_length, packet->payload);
                }
            }
            break;
            
        case MQTT_SUBSCRIBE:
            printf("  [MQTT] Packet ID: %d\n", packet->packet_id);
            printf("  [MQTT] Topics:\n");
            for (int i = 0; i < packet->subscribe_count; i++) {
                printf("    - %s (QoS %d)\n", 
                       packet->subscribe_topics[i], 
                       packet->subscribe_qos[i]);
            }
            break;
    }
}
```

## Initialization and Usage

### Initialization:
```c
int mqtt_parser_init(void) {
    // Reset global statistics
    memset(&global_mqtt_stats, 0, sizeof(mqtt_statistics_t));
    
    printf("[MQTT Parser] Initialized\n");
    return 0;
}
```

### Usage Example:
```c
// Initialize parser
mqtt_parser_init();

// Check if traffic is MQTT
if (is_mqtt_traffic(src_port, dst_port, payload, payload_len)) {
    // Parse MQTT packet
    mqtt_packet_t mqtt_pkt;
    if (mqtt_parse_packet(payload, payload_len, &mqtt_pkt) == 0) {
        // Successfully parsed
        mqtt_print_packet(&mqtt_pkt);
        
        // Check for anomalies
        char anomaly[512];
        if (mqtt_detect_anomalies(&mqtt_pkt, anomaly, sizeof(anomaly))) {
            printf("  [SECURITY] Anomaly detected: %s\n", anomaly);
        }
        
        // Free dynamically allocated payload
        if (mqtt_pkt.payload) {
            free(mqtt_pkt.payload);
        }
    } else {
        printf("  [MQTT] Parse error: %s\n", mqtt_pkt.error_message);
    }
}

// Get statistics
mqtt_statistics_t stats;
mqtt_get_statistics(&stats);
printf("Total MQTT packets: %lu\n", stats.total_packets);
printf("PUBLISH messages: %lu\n", stats.publish_count);
printf("Malformed packets: %lu\n", stats.malformed_packets);

// Cleanup
mqtt_parser_cleanup();
```

## Integration with DPI Engine

The MQTT parser is integrated into the DPI Engine for automatic MQTT detection:

```c
// In DPI Engine packet processing
if (parsed->layer3.protocol == IPPROTO_TCP && 
    (parsed->layer4.src_port == 1883 || parsed->layer4.dst_port == 1883)) {
    
    // Extract MQTT payload
    const uint8_t *mqtt_payload = get_payload(parsed);
    uint32_t mqtt_payload_len = get_payload_length(parsed);
    
    // Parse MQTT packet
    mqtt_packet_t mqtt_pkt;
    if (mqtt_parse_packet(mqtt_payload, mqtt_payload_len, &mqtt_pkt) == 0) {
        // Store MQTT information in parsed packet
        parsed->is_mqtt = 1;
        parsed->mqtt_packet_type = mqtt_pkt.packet_type;
        
        if (mqtt_pkt.packet_type == MQTT_PUBLISH) {
            strncpy(parsed->mqtt_topic, mqtt_pkt.topic, 
                   sizeof(parsed->mqtt_topic) - 1);
            parsed->mqtt_payload_length = mqtt_pkt.payload_length;
        }
        
        if (mqtt_pkt.packet_type == MQTT_CONNECT) {
            strncpy(parsed->mqtt_client_id, mqtt_pkt.client_id, 
                   sizeof(parsed->mqtt_client_id) - 1);
        }
        
        // Free allocated payload
        if (mqtt_pkt.payload) free(mqtt_pkt.payload);
    }
}
```

## Performance Considerations

### Memory Management:
- **Stack Allocation**: Fixed-size fields (topic, client ID, etc.)
- **Dynamic Allocation**: PUBLISH payloads (can be large)
- **Memory Leak Prevention**: Always free `mqtt_pkt.payload` after use

### Parsing Efficiency:
- **Single-pass Parsing**: Reads data sequentially
- **O(N) Complexity**: Linear with packet size
- **Minimal Copying**: Uses pointers where possible

### Error Handling:
- Validates all length fields before access
- Checks buffer boundaries
- Returns descriptive error messages
- Tracks malformed packets in statistics

## Security Features

### Attack Detection:
1. **Command Injection**: Detects shell/script patterns in topics
2. **Path Traversal**: Detects directory navigation attempts
3. **Buffer Overflow**: Validates all lengths before parsing
4. **DoS Prevention**: Limits on topic/payload sizes
5. **Malformed Packets**: Tracks and reports parse failures

### Best Practices:
- Always validate topic names before use
- Limit payload sizes in production
- Monitor anomaly statistics
- Sanitize client IDs and usernames
- Use TLS (port 8883) for sensitive data

## Standards Compliance

### Supported Versions:
- **MQTT v3.1** (Protocol ID: 3, Protocol Name: "MQIsdp")
- **MQTT v3.1.1** (Protocol ID: 4, Protocol Name: "MQTT")

### Protocol References:
- MQTT v3.1.1 Specification: [OASIS Standard](http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)
- MQTT v3.1 Specification: [IBM developerWorks](https://www.ibm.com/support/pages/mqtt-v31-protocol-specification)

## Dependencies

- Standard C libraries: stdio.h, stdlib.h, string.h, arpa/inet.h

## Files

### Headers
- `mqtt_parser.h`: Main interface and data structures

### Implementation
- `mqtt_parser.c`: Core parsing logic
- `mqtt_integration.c`: Integration with DPI Engine
- `mqtt_reports.c`: Report generation for MQTT traffic

## Future Enhancements

1. **MQTT v5.0 Support**: Add support for latest MQTT version
2. **Payload Decoders**: JSON, Protocol Buffer, etc.
3. **Topic Pattern Analysis**: Statistical topic usage patterns
4. **Session Tracking**: Track client sessions across connections
5. **QoS Validation**: Verify QoS handshake correctness
6. **Compression Support**: Handle compressed payloads
7. **Authentication Analysis**: Track auth success/failure rates
8. **Broker Emulation**: Active response to MQTT clients
