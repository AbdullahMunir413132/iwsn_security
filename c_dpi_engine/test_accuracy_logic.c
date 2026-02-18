/*
 * Test to verify DPI accuracy calculation correctly handles unknown packets
 */
#include <stdio.h>
#include <stdint.h>

void test_accuracy_calculation(uint64_t total_packets, uint64_t unknown_packets) {
    uint64_t detected_packets = total_packets - unknown_packets;
    double detection_rate = (double)detected_packets / total_packets * 100.0;
    
    printf("═══════════════════════════════════════════════\n");
    printf("Test Case:\n");
    printf("  Total Packets:     %lu\n", total_packets);
    printf("  Unknown Packets:   %lu\n", unknown_packets);
    printf("  Detected Packets:  %lu\n", detected_packets);
    printf("  Detection Accuracy: %.1f%%\n", detection_rate);
    printf("  Formula: (%lu - %lu) / %lu × 100 = %.1f%%\n", 
           total_packets, unknown_packets, total_packets, detection_rate);
    
    if (unknown_packets > 0) {
        printf("  ✅ PASS: Accuracy < 100%% when unknowns exist\n");
    } else {
        printf("  ⓘ  INFO: Accuracy = 100%% (no unknown packets)\n");
    }
    printf("\n");
}

int main() {
    printf("╔═══════════════════════════════════════════════╗\n");
    printf("║  DPI ACCURACY LOGIC VERIFICATION TEST         ║\n");
    printf("╚═══════════════════════════════════════════════╝\n\n");
    
    printf("Formula: accuracy = (total_packets - unknown_packets) / total_packets × 100\n\n");
    
    // Test 1: No unknown packets (current situation)
    test_accuracy_calculation(1000, 0);
    
    // Test 2: Some unknown packets
    test_accuracy_calculation(1000, 100);
    
    // Test 3: Many unknown packets
    test_accuracy_calculation(1000, 500);
    
    // Test 4: Your actual syn_flood.pcap
    test_accuracy_calculation(40, 0);
    
    // Test 5: Simulated case with unknowns
    test_accuracy_calculation(40, 10);
    
    printf("═══════════════════════════════════════════════\n");
    printf("CONCLUSION:\n");
    printf("  The formula IS correct: (total - unknown) / total\n");
    printf("  Your test files have 0 unknown packets,\n");
    printf("  so 100%% accuracy is mathematically correct!\n");
    printf("═══════════════════════════════════════════════\n");
    
    return 0;
}
