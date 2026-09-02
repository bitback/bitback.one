# www/tools/update-crypto-hash.sh

## Po co

Przelicza skrót SHA-384 pliku `crypto.js` i wstawia go w każdym miejscu, gdzie jest deklarowany: w atrybucie sprawdzania integralności zasobu w `index.php` i `view.php` oraz w sekcji weryfikacyjnej `README.md` i `SECURITY.md`. Niezgodność tego skrótu z serwowanym plikiem kończy się zablokowaniem kryptografii przez przeglądarkę, czyli leżącą aplikacją, więc podmiana skrótu nie może zostać po ludzku pominięta.

## Wywołanie

Z korzenia kodu aplikacji: `bash tools/update-crypto-hash.sh`. Skrypt pisze wprost do wymienionych plików; zmianę ogląda się potem przez `git diff`.

## Kiedy odpalać

Po każdej zmianie w `crypto.js`, przed commitem.

## Nie sprawdza

Nie sprawdza, czy `crypto.js` jest poprawny ani czy trzyma kontrakt formatu - liczy skrót tego, co zastanie, więc plik zepsuty dostanie zielony skrót zepsutej treści (parytet ze złotym wektorem pilnuje `interop/gen/verify-vectors.mjs`, a wdrożenie odmawia startu bez niego). Nie rusza skrótów innych zasobów niż `crypto.js`: w plikach PHP podmienia wyłącznie linie, w których nazwa tego pliku występuje. Nie zakłada sekcji weryfikacyjnej w plikach tekstowych - gdy pełnego skrótu tam nie ma, wypisuje notatkę i idzie dalej.

## Kotwice

Wynik przestaje znaczyć, gdy zmieni się układ miejsc deklarujących skrót: skrypt zna cztery pliki wpisane w kod (`index.php`, `view.php`, `README.md`, `SECURITY.md`), a bramka wdrożeniowa liczy wystąpienia i wymaga dokładnie pięciu - dołożenie albo usunięcie miejsca rozjeżdża te dwie liczby. W plikach tekstowych podmieniany jest tylko pełny skrót o długości sześćdziesięciu czterech znaków base64, bo dopasowanie do skróconego zapisu w prozie doklejało skrót w środek zdania przy każdym przebiegu. Zależy od dostępności `openssl` w powłoce i od tego, że algorytmem integralności pozostaje SHA-384.
