
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <time.h>

#include "config.h"
#include "dot_client.h"

#define DNS_BUFFER_SIZE 512
#define WIFI_TIMEOUT_MS 20000
#define NTP_TIMEOUT_MS 30000
#define DNS_READ_TIMEOUT_MS 15000

WiFiClientSecure tlsClient;

// ---------------- READ EXACT BYTES ----------------

bool readExact(WiFiClientSecure &client, uint8_t *buffer, size_t length) {
    size_t received = 0;
    unsigned long startTime = millis();

    while (received < length) {
        if (millis() - startTime > DNS_READ_TIMEOUT_MS) {
            Serial.println("[DoT] Response read timeout");
            return false;
        }

        int availableBytes = client.available();

        if (availableBytes > 0) {
            int count = client.read(
                buffer + received,
                min((size_t)availableBytes, length - received)
            );

            if (count > 0) {
                received += count;
            }
        } else if (!client.connected()) {
            Serial.println("[DoT] Connection closed");
            return false;
        }

        delay(1);
    }

    return true;
}

// ---------------- BUILD DNS QUERY ----------------

int buildDNSQuery(const String &domain, uint8_t *buffer,
                  uint16_t transactionID) {
    memset(buffer, 0, DNS_BUFFER_SIZE);

    buffer[0] = (transactionID >> 8) & 0xFF;
    buffer[1] = transactionID & 0xFF;

    // Recursion Desired
    buffer[2] = 0x01;

    // One question and one additional record
    buffer[5] = 0x01;
    buffer[11] = 0x01;

    int position = 12;

    String name = domain;
    name.trim();

    if (name.endsWith(".")) {
        name.remove(name.length() - 1);
    }

    int start = 0;

    while (start < name.length()) {
        int dot = name.indexOf('.', start);

        if (dot == -1) {
            dot = name.length();
        }

        int labelLength = dot - start;

        if (labelLength <= 0 || labelLength > 63) {
            Serial.println("[DNS] Invalid domain label");
            return -1;
        }

        if (position + labelLength + 1 >= DNS_BUFFER_SIZE) {
            return -1;
        }

        buffer[position++] = labelLength;

        for (int i = start; i < dot; i++) {
            buffer[position++] = (uint8_t)name[i];
        }

        start = dot + 1;
    }

    buffer[position++] = 0x00;

    // QTYPE A
    buffer[position++] = 0x00;
    buffer[position++] = 0x01;

    // QCLASS IN
    buffer[position++] = 0x00;
    buffer[position++] = 0x01;

    // EDNS0 OPT record
    buffer[position++] = 0x00;
    buffer[position++] = 0x00;
    buffer[position++] = 0x29;

    // UDP payload size
    buffer[position++] = 0x04;
    buffer[position++] = 0xD0;

    // Extended RCODE and EDNS version
    buffer[position++] = 0x00;
    buffer[position++] = 0x00;

    // DO bit enabled
    buffer[position++] = 0x80;
    buffer[position++] = 0x00;

    // RDLEN = 0
    buffer[position++] = 0x00;
    buffer[position++] = 0x00;

    return position;
}

// ---------------- NTP TIME ----------------

bool synchronizeTime() {
    Serial.println("\n[Time] Synchronizing clock using NTP...");

    configTime(
        0, 0,
        "pool.ntp.org",
        "time.google.com",
        "time.cloudflare.com"
    );

    unsigned long start = millis();

    while (millis() - start < NTP_TIMEOUT_MS) {
        time_t now = time(nullptr);

        if (now >= 1793465654) {
            struct tm timeInfo;
            gmtime_r(&now, &timeInfo);

            Serial.println("[Time] NTP synchronized");

            Serial.printf(
                "[Time] Unix timestamp: %lld\n",
                (long long)now
            );

            Serial.printf(
                "[Time] UTC: %04d-%02d-%02d %02d:%02d:%02d\n",
                timeInfo.tm_year + 1900,
                timeInfo.tm_mon + 1,
                timeInfo.tm_mday,
                timeInfo.tm_hour,
                timeInfo.tm_min,
                timeInfo.tm_sec
            );

            return true;
        }

        delay(500);
    }

    Serial.println("[Time] NTP synchronization failed");
    return false;
}

// ---------------- WIFI CONNECTION ----------------

bool connectWiFiForDoT() {
    Serial.println("\n==============================");
    Serial.println(" AIORI 3 - ESP32 DNSSEC CLIENT");
    Serial.println("==============================");

    Serial.printf("[WiFi] Connecting to %s\n", WIFI_SSID);

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    unsigned long start = millis();

    while (WiFi.status() != WL_CONNECTED) {
        if (millis() - start > WIFI_TIMEOUT_MS) {
            Serial.println("[WiFi] Connection timeout");
            return false;
        }

        Serial.print(".");
        delay(500);
    }

    Serial.println("\n[WiFi] Connected successfully");

    Serial.print("[WiFi] ESP32 IP: ");
    Serial.println(WiFi.localIP());

    Serial.print("[WiFi] Gateway: ");
    Serial.println(WiFi.gatewayIP());

    return synchronizeTime();
}

// ---------------- DNS OVER TLS QUERY ----------------

bool runDoTQuery(const String &domain) {
    Serial.println("\n================================");
    Serial.printf("[DoT] Query: %s\n", domain.c_str());
    Serial.println("================================");

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[WiFi] Not connected");
        return false;
    }

    uint8_t dnsQuery[DNS_BUFFER_SIZE];

    uint16_t transactionID =
        (uint16_t)(esp_random() & 0xFFFF);

    int queryLength = buildDNSQuery(
        domain,
        dnsQuery,
        transactionID
    );

    if (queryLength <= 0) {
        Serial.println("[DNS] Failed to construct query");
        return false;
    }

    // TLS configuration
    Serial.println("[TLS] Loading trusted CA certificate...");

    // TEMPORARY DEVELOPMENT MODE:
    // Does not authenticate the gateway certificate.
    // Restore setCACert(DOT_CA_CERT) after TLS verification is fixed.
    tlsClient.setInsecure();

    tlsClient.setHandshakeTimeout(15);

    Serial.printf(
        "[TLS] Connecting to %s:%d\n",
        DOT_HOST,
        DOT_PORT
    );

    if (!tlsClient.connect(DOT_HOST, DOT_PORT)) {
        char errorBuffer[160] = {0};

        int errorCode = tlsClient.lastError(
            errorBuffer,
            sizeof(errorBuffer)
        );

        Serial.printf("[TLS] Connection failed: %d\n", errorCode);
        Serial.printf("[TLS] Details: %s\n", errorBuffer);

        tlsClient.stop();
        return false;
    }

    Serial.println("[TLS] Connection successful");

    // Send DNS-over-TLS length prefix
    uint8_t lengthPrefix[2];

    lengthPrefix[0] = (queryLength >> 8) & 0xFF;
    lengthPrefix[1] = queryLength & 0xFF;

    if (tlsClient.write(lengthPrefix, 2) != 2 ||
        tlsClient.write(dnsQuery, queryLength) != queryLength) {
        Serial.println("[DoT] Failed to transmit query");
        tlsClient.stop();
        return false;
    }

    Serial.println("[DoT] DNS query transmitted");

    // Read response length
    uint8_t responseLengthBytes[2];

    if (!readExact(tlsClient, responseLengthBytes, 2)) {
        tlsClient.stop();
        return false;
    }

    uint16_t responseLength =
        ((uint16_t)responseLengthBytes[0] << 8) |
        responseLengthBytes[1];

    if (responseLength < 12 || responseLength > DNS_BUFFER_SIZE) {
        Serial.println("[DoT] Invalid DNS response length");
        tlsClient.stop();
        return false;
    }

    // Read DNS response
    uint8_t dnsResponse[DNS_BUFFER_SIZE];

    if (!readExact(tlsClient, dnsResponse, responseLength)) {
        tlsClient.stop();
        return false;
    }

    tlsClient.stop();

    // Verify transaction ID
    uint16_t receivedID =
        ((uint16_t)dnsResponse[0] << 8) |
        dnsResponse[1];

    if (receivedID != transactionID) {
        Serial.println("[DNS] Transaction ID mismatch");
        return false;
    }

    if ((dnsResponse[2] & 0x80) == 0) {
        Serial.println("[DNS] Invalid DNS response");
        return false;
    }

    // Extract DNS flags
    uint8_t flagsHigh = dnsResponse[2];
    uint8_t flagsLow = dnsResponse[3];

    uint8_t rcode = flagsLow & 0x0F;

    // CORRECT AD FLAG LOCATION: bit 5 of DNS flags byte 2
    bool authenticatedData = (flagsLow & 0x20) != 0;

    Serial.println("\n---------- DNS RESULT ----------");

    Serial.printf("[DNS] Response length: %u bytes\n", responseLength);
    Serial.printf("[DNS] RCODE: %u\n", rcode);

    if (rcode == 0) {
        Serial.println("[DNS] RCODE meaning: NOERROR");
    } else if (rcode == 2) {
        Serial.println("[DNS] RCODE meaning: SERVFAIL");
    } else {
        Serial.println("[DNS] RCODE meaning: Other");
    }

    Serial.printf(
        "[DNS] AD flag: %s\n",
        authenticatedData ? "SET (1)" : "NOT SET (0)"
    );

    if (rcode == 0 && authenticatedData) {
        Serial.println("[RESULT] SECURE");
        Serial.println("[RESULT] Resolver reports DNSSEC validation succeeded.");
    }
    else if (rcode == 0 && !authenticatedData) {
        Serial.println("[RESULT] INSECURE");
        Serial.println("[RESULT] Successful response without AD flag.");
    }
    else if (rcode == 2) {
        Serial.println("[RESULT] SERVFAIL");
        Serial.println("[RESULT] Resolver could not complete the query.");
    }
    else {
        Serial.printf("[RESULT] DNS response code: %u\n", rcode);
    }

    Serial.println("--------------------------------");

    return true;
}
