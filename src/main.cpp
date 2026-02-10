#include <WiFi.h>
#include <SD.h>
#include <esp_wifi.h>
#include <DNSServer.h>
#include "types.h"
#include "web_interface.h"
#include "deauth.h"
#include "definitions.h"

DNSServer dnsServer;
int curr_channel = 1;

// Funzione helper per salvare su SD
void save_pending_packets() {
  // Finché l'indice di lettura è diverso da quello di scrittura, c'è roba da salvare
  while (buffer_tail != buffer_head) {
    
    // 1. Apri file 
    File dumpFile = SD.open("/capture.txt", FILE_APPEND);
    if (dumpFile) {
      PacketBuffer *pkt = &packet_buffer[buffer_tail];

      // --- FORMATTAZIONE PER text2pcap ---
      // Ci fermiamo 4 byte prima della fine per scartare il checksum (FCS)
      // Aggiungiamo un controllo di sicurezza (pkt->len > 4) per evitare crash su pacchetti corrotti minuscoli

      int real_length = pkt->len;
      if (real_length > 4) {
        real_length -= 4; 
      }
      
      // 2. Formatta e Scrivi
      dumpFile.println("#Pacchetto EAPOL/Beacon"); 
      for (int k = 0; k < real_length; k++) {
         if (k % 16 == 0) {
            if (k > 0) dumpFile.println();
            dumpFile.printf("%06X ", k);
         }
         dumpFile.printf("%02X ", pkt->data[k]);
      }
      dumpFile.println(); 
      dumpFile.println(); 
      dumpFile.close();

      #ifdef SERIAL_DEBUG
      Serial.println(">>> Pacchetto salvato su SD con successo!");
      #endif
    } else {
      #ifdef SERIAL_DEBUG
      Serial.println("Errore apertura SD!");
      #endif
    }

    // 3. Avanza l'indice di lettura
    buffer_tail = (buffer_tail + 1) % MAX_BUFFER_SIZE;
  }
}

void setup() {
#ifdef SERIAL_DEBUG
  Serial.begin(115200);
#endif

  // --- INIZIALIZZAZIONE SD ---
  if (!SD.begin()) { 
    Serial.println("SD Card Mount Failed");
  } else {
    Serial.println("SD Card Mount Success");
  }

  WiFi.mode(WIFI_MODE_AP);
  WiFi.softAP(AP_SSID, AP_PASS);

  dnsServer.start(53, "*", WiFi.softAPIP());

  start_web_interface();
}

void loop() {
  dnsServer.processNextRequest();
  
  save_pending_packets();

  web_interface_handle_client();

  if (deauth_type == DEAUTH_TYPE_ALL) {
    if (curr_channel > CHANNEL_MAX) curr_channel = 1;
    esp_wifi_set_channel(curr_channel, WIFI_SECOND_CHAN_NONE);
    curr_channel++;
    delay(10);
  } 
}