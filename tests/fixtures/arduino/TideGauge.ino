// Tide gauge float sensor for Saltmere Harbour.
#include <Wire.h>

#define SENSOR_PIN A0

int lastLevel = 0;

void setup() {
  Serial.begin(9600);
}

void loop() {
  lastLevel = analogRead(SENSOR_PIN); // raw level
  Serial.println(lastLevel);
  delay(1000);
}
