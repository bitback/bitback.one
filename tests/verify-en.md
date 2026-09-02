# www/tests/verify-en.ps1

## Po co

Sprawdza, że wersja angielska nie przecieka polskimi tekstami. Renderuje każdą stronę widzianą przez użytkownika w wariancie angielskim i szuka w niej fraz z listy zakazanej. Lista powstaje z dwóch źródeł: przetłumaczonych wartości słownika (zrzucanych z PHP) i gałęzi warunkowych w widoku (plik `tests/en-blocklist.json`). Dodatkowo raportuje resztkowe polskie znaki diakrytyczne w widocznym tekście - to sygnał do kontroli wzrokowej, nie powód niepowodzenia, bo mogą pochodzić z komentarzy w kodzie.

## Wywołanie

Z PowerShell: `.\www\tests\verify-en.ps1`. Skrypt startuje własny serwer PHP z katalogiem danych w miejscu tymczasowym, więc chodzi samodzielnie, poza główną suitą. Wymaga PHP CLI (ścieżka nadpisywalna przez `$env:BB_PHP`). Wyjście zerowe oznacza brak wycieków.

## Kiedy odpalać

Po każdej zmianie w tekstach interfejsu, w słowniku tłumaczeń i w gałęziach warunkowych widoku, oraz po dołożeniu nowej strony widzianej przez użytkownika.

## Nie sprawdza

Nie sprawdza poprawności ani stylu angielszczyzny - wyłącznie nieobecność polskich fraz i obecność oczekiwanej frazy angielskiej na każdej badanej stronie. Frazy krótsze niż pięć znaków są odsiewane jako zbyt ogólne do bezpiecznego szukania podciągu, więc krótkie polskie słowo przejdzie niezauważone. Przed porównaniem czyści treść z komentarzy HTML, CSS i jednoliniowych komentarzy JavaScript, więc polszczyzna schowana w komentarzu nie jest wyciekiem. Bada strony renderowane po stronie serwera; tekst wstawiany dopiero przez skrypt w przeglądarce jest poza zasięgiem. Rekordy do badania zapisuje wprost do katalogu danych, omijając zabezpieczenie przed automatami, więc nie mówi nic o zachowaniu tego zabezpieczenia.

## Kotwice

Wynik przestaje znaczyć, gdy zniknie któreś ze źródeł listy zakazanej: zrzut słownika przez `tests/dump-i18n-diff.php` albo plik `tests/en-blocklist.json` z gałęziami warunkowymi - tego drugiego nikt nie odświeża sam, więc nowa gałąź w widoku wymaga ręcznego dopisania frazy. Przełącznik języka jest przyjęty jako parametr adresu; zmiana sposobu wyboru języka unieważnia cały przebieg. W pliku skryptu celowo nie ma polskich literałów, bo PowerShell 5.1 czyta skrypt bez znacznika kolejności bajtów jako stronę kodową ANSI i psułby polskie znaki - listy polskie żyją jako dane w UTF-8. Domyślna ścieżka PHP i pula portów są wpisane w kod.
