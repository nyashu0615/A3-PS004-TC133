
#ifndef DOT_CLIENT_H
#define DOT_CLIENT_H

#include <Arduino.h>

// Connect ESP32 to Wi-Fi
bool connectWiFiForDoT();

// Send a DNS query through the authenticated DoT gateway
bool runDoTQuery(const String &domain);

#endif
