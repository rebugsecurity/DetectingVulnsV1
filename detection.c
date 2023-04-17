#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nmap.h>

// Callback function to handle the results of the vulnerability scan
int vuln_callback(struct NmapRun *run, struct NmapHost *host, struct NmapResult *result) {
    // Iterate through the vulnerabilities detected
    for (int i = 0; i < result->vulns->length; i++) {
        struct NmapVuln *vuln = (struct NmapVuln *)result->vulns->list[i];

        // Extract relevant information from the vulnerability
        char *name = vuln->name;
        char *description = vuln->description;

        // Print the vulnerability information
        printf("Vulnerability: %s\n", name);
        printf("Description: %s\n", description);
        printf("---------------------------------------------------\n");
    }

    return 0;
}

int main() {
    // Initialize Nmap library
    if (!nmap_init()) {
        fprintf(stderr, "Failed to initialize Nmap library: %s\n", nmap_strerror());
        return 1;
    }

    // Create Nmap options
    struct NmapOptions *options = nmap_options_create();
    if (!options) {
        fprintf(stderr, "Failed to create Nmap options: %s\n", nmap_strerror());
        nmap_cleanup();
        return 1;
    }

    // Set target hosts to scan
    nmap_options_set_targets(options, "192.168.1.1-255");

    // Enable vulnerability scanning
    nmap_options_enable_vuln_scan(options);

    // Run the vulnerability scan
    struct NmapRun *run = nmap_run(options);
    if (!run) {
        fprintf(stderr, "Failed to run Nmap: %s\n", nmap_strerror());
        nmap_options_destroy(options);
        nmap_cleanup();
        return 1;
    }

    // Process the scan results
    nmap_run_loop(run, vuln_callback);

    // Clean up Nmap resources
    nmap_run_destroy(run);
    nmap_options_destroy(options);
    nmap_cleanup();

    return 0;
}