# Super Clean V30

V30 završava konačni A4 račun i štampu etiketa.

## Račun
- A4 poslovni format.
- N123 je glavni broj narudžbe.
- Broj tepiha se automatski računa.
- Stavke mjerenja i dostava prikazuju se odvojeno.
- Gotovinsko i kartično plaćanje ne prikazuju datum dospijeća.
- Žiralno plaćanje zahtijeva datum dospijeća i prikazuje ga na računu.
- Račun se može štampati tek nakon snimanja.

## Etikete
- Svaki tepih dobija posebnu etiketu.
- N123 i redni broj tepiha (npr. 1/3) su jasno istaknuti.
- Etiketa sadrži logo, broj firme, kupca, telefon kupca, adresu, uslugu, dimenziju i QR.
- QR je vezan za konkretan tepih.
- Pri štampi na A4 koriste se kompaktne etikete približno 96 × 67 mm, dvije po širini.

## Provjera
`node --check server.js`

`node --check public/app.js`


## V31 testni scenario

Za provjeru računa i etiketa koristi jedan stvarni testni kupac i narudžbu sa:

- 3 izmjerena tepiha
- dostavom, npr. 10.00 KM
- cijenom pranja iz cjenovnika
- gotovinskim plaćanjem za prvi test
- žiralnim plaćanjem za drugi test i datumom dospijeća

Očekivano:

1. Račun prikazuje `N123` kao broj narudžbe.
2. `Br. tepiha` prikazuje `3 kom.`.
3. Dostava je zasebna stavka.
4. Ukupan iznos je zbir tepiha i dostave.
5. Kod žiralnog se prikazuje datum dospijeća.
6. Svaka etiketa ima `N123` i `1/3`, `2/3`, `3/3`.
7. QR sa etikete `2/3` otvara baš drugi tepih.
8. Nakon QR otvaranja aplikacija evidentira broj skeniranja i vrijeme.
9. Administrator može vidjeti `QR_SCAN` u Dnevniku aktivnosti.


## V32 — kompletan test i oporavak

Administratorski modul sada ima:
- **Pokreni test sistema** — u transakciji provjerava kupca, narudžbu, N-broj, mjerenje, obračun, dostavu, račun, datum dospijeća i generisanje QR-a. Testni podaci se uvijek poništavaju.
- **Vrati backup** — administrator može odabrati prethodno preuzet Super Clean JSON backup. Vraćanje zamjenjuje poslovne podatke iz backupa i nakon uspješnog vraćanja korisnik se automatski odjavljuje.
- QR broj skeniranja (`qr_scan_count` i `last_qr_scanned_at`) sada je dio backupa.

Prije vraćanja backupa aplikacija traži potvrdu. Preporuka je da se prije restore-a napravi novi ručni backup trenutnog stanja.
