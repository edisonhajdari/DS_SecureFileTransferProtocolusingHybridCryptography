README - Secure File Transfer System

Përmbajtja:

Përshkrimi i Aplikacionit  

Konfigurimi dhe Instalimi  

Përdorimi  

Zgjedhjet Kriptografike  

Etapat e Protokollit  

Referencat  

1. Përshkrimi i Aplikacionit
Ky është një sistemi i sigurt për transferimin e skedarëve mes një klienti dhe një serveri në një rrjet lokal. Klienti mund të zgjedhë një skedar për transferim, dhe pastaj skedari i enkriptuar dhe i nënshkruar dërgohet në server.

2. Konfigurimi dhe Instalimi
Klienti
Sigurohuni që të keni instaluar një version të Java Runtime Environment (JRE) ose Java Development Kit (JDK) në kompjuterin tuaj.
Shkarkoni dhe shfaqni kodin për klientin.
Ekzekutoni programin duke ekzekutuar klasën SecureFileTransferClient.
Serveri
Sigurohuni që të keni instaluar një version të Java Runtime Environment (JRE) ose Java Development Kit (JDK) në serverin tuaj.
Shkarkoni dhe shfaqni kodin për serverin.
Ekzekutoni programin duke ekzekutuar klasën SecureFileTransferServer.

3. Përdorimi
Pasi të jetë konfiguruar dhe ekzekutuar klienti dhe serveri, përdoruesi mund të ndjekë këto hapa për të transferuar një skedar:
Hapni klientin dhe zgjidhni një skedar për transferim duke përdorur butonin "Browse".
Klikoni butonin "Transfer" për të filluar transferimin.
Pas përfundimit të transferimit, përdoruesi do të marrë një mesazh konfirmimi për suksesin e operacionit.
4. Zgjedhjet Kriptografike
Për të siguruar transferimin e sigurt të skedarëve, ky sistem përdor disa zgjedhje kriptografike:
RSA për shkëmbimin e çelësave: Çelësat RSA përdoren për të shkëmbyer çelësat e enkriptimit AES mes klientit dhe serverit.
AES për enkriptimin e skedarëve: Skedarët zgjedhur për transferim enkriptohen me algoritmin AES për të siguruar privatësi.
SHA-256 dhe RSA për nënshkrimin dhe verifikimin e skedarëve: Për të siguruar autenticitetin dhe integritetin e skedarit, skedarët nënshkruhen me algoritmin SHA-256 dhe nënshkruhen me çelësat RSA.

5. Etapat e Protokollit
Shkëmbimi i çelësave: Klienti dhe serveri shkëmbejnë çelësat publikë RSA.
Shkëmbimi i çelësve AES: Klienti gjeneron një çelës AES dhe e enkripton atë me çelësin publik RSA të serverit për t'i dërguar në server.
Transferimi i skedarit: Klienti zgjedh një skedar për transferim, e enkripton atë me çelësin AES dhe e nënshkruan me çelësin privat RSA të tij. Pastaj, skedari i enkriptuar dhe i nënshkruar dërgohet në server.
Verifikimi i nënshkrimit dhe marrja e skedarit: Serveri verifikon nënshkrimin e skedarit dhe pastaj e ruaj skedarin në server.

6. Referencat
[1] Oracle. "Java Cryptography Architecture (JCA) Reference Guide." Online. Accessed May 22, 2024.
[2] Baeldung. "RSA Encryption and Decryption in Java." Online. Accessed May 22, 2024.
[3] Baeldung. "AES Encryption and Decryption in Java." Online. Accessed May 22, 2024.
[4] Baeldung. "Digital Signatures in Java." Online. Accessed May 22, 2024.
