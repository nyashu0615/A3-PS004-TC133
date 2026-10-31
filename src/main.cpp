
#include <Arduino.h>
#include "dot_client.h"

// DNSSEC test domains
const char *testDomains[] = {
    "cloudflare.com",
    "unsigned.test",
    "dnssec-failed.org"
};

const int TOTAL_TESTS = 3;

void runInitialTests() {
    Serial.println("\n========================================");
    Serial.println(" AIORI 3 - DNSSEC TESTING SYSTEM");
    Serial.println(" Authenticated Gateway-Assisted DNSSEC");
    Serial.println("========================================");

    Serial.println("\nRunning three DNSSEC test cases...");

    for (int i = 0; i < TOTAL_TESTS; i++) {
        Serial.println("\n----------------------------------------");
        Serial.printf("TEST CASE %d OF %d\n", i + 1, TOTAL_TESTS);
        Serial.println("----------------------------------------");

        Serial.printf("Testing domain: %s\n", testDomains[i]);

        bool result = runDoTQuery(String(testDomains[i]));

        if (!result) {
            Serial.println("[TEST] Query execution failed.");
        }

        delay(1500);
    }

    Serial.println("\n========================================");
    Serial.println(" ALL INITIAL TESTS COMPLETED");
    Serial.println("========================================");

    Serial.println("\nEnter a domain name in Serial Monitor");
    Serial.println("and press Send to perform another query.");
}

void setup() {
    Serial.begin(115200);
    delay(1500);

    Serial.println("\n\nBooting AIORI 3 DNSSEC Client...");

    if (!connectWiFiForDoT()) {
        Serial.println("\n[ERROR] Wi-Fi or NTP initialization failed.");
        return;
    }

    runInitialTests();
}

void loop() {
    if (Serial.available()) {
        String domain = Serial.readStringUntil('\n');
        domain.trim();

        if (domain.length() > 0) {
            Serial.println("\n[USER] Custom DNS query received.");
            runDoTQuery(domain);

            Serial.println("\nEnter another domain:");
        }
    }
}
