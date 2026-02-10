#ifndef TYPES_H
#define TYPES_H

#define MAX_BUFFER_SIZE 10 // Salviamo massimo 10 pacchetti in coda (bastano per un handshake)
#define MAX_PACKET_LEN 512 // Dimensione massima di un pacchetto EAPOL (di solito sono < 200 byte)

typedef struct {
  uint8_t data[MAX_PACKET_LEN];
  uint16_t len;
} PacketBuffer;

// Variabili globali per la gestione del buffer (dichiarate extern per essere visibili ovunque)
extern PacketBuffer packet_buffer[MAX_BUFFER_SIZE];
extern volatile int buffer_head; // Indice di scrittura (ISR)
extern volatile int buffer_tail; // Indice di lettura (Loop)

typedef struct {
  uint8_t frame_control[2] = { 0xC0, 0x00 };
  uint8_t duration[2];
  uint8_t station[6];
  uint8_t sender[6];
  uint8_t access_point[6];
  uint8_t fragment_sequence[2] = { 0xF0, 0xFF };
  uint16_t reason;
} deauth_frame_t;

typedef struct {
  uint16_t frame_ctrl;
  uint16_t duration;
  uint8_t dest[6];
  uint8_t src[6];
  uint8_t bssid[6];
  uint16_t sequence_ctrl;
  uint8_t addr4[6];
} mac_hdr_t;

typedef struct {
  mac_hdr_t hdr;
  uint8_t payload[0];
} wifi_packet_t;

const wifi_promiscuous_filter_t filt = {
  .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
};

#endif