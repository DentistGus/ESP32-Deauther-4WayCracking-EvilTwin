# ESP32-Deauther-4WayCracking-EvilTwin
L’obiettivo di questo elaborato è stato quello di costruire un dispositivo portatile basato sul microcontrollore ESP32 per testare la sicurezza delle reti WPA2-PSK. 
In particolare il focus è stato posto sulla possibilità da parte dell’ESP32 di **deautenticare** i 
dispositivi client dall’AP target costringendo la vittima a connettere il proprio dispositivo ad una rete fittizia (senza password) con lo stesso SSID dell’AP sottoposto all’attacco. L’attacco tuttavia non finisce qui in quanto lo stesso ESP32 è stato
configurato per catturare l’intero **4-Way Handshake** che avviene tra l’AP target e i vari dispositivi client ad esso connessi.

Il progetto dunque copre sia l’attacco di tipo **Social Engineering** attraverso la costruzione dell’**Evil Twin** sia l’attacco crittografico attraverso la cattura del 4-Way
Handshake e il successivo *cracking* della password. 

È doveroso specificare che tutti i test sono stati condotti esclusivamente su reti di mia
proprietà e a scopo puramente didattico.

Non mancheranno inoltre considerazioni su una possibile strategia di difesa da un
attacco simile, mutando il protocollo di sicurezza o avviando un’attività di monitoraggio.
