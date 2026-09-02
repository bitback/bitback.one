# www/tests/e2e-view.ps1

## Po co

Sprawdza od strony przeglądarki te ścieżki widoku, których nie pokrywa główna suita: formularz hasła (wysłanie liczy funkcję wyprowadzania klucza, wysyła znacznik uwierzytelniający i korzysta z pamięci sesji), zapytanie wewnętrzne jako droga zapasowa przy braku klucza nadrzędnego w trybie prywatnym przeglądarki, uszkodzony fragment adresu oraz link bez hasła. Steruje przeglądarką przez całą drogę: od utworzenia linku po odszyfrowanie treści. Osobno od głównej suity, bo wymaga routera przekierowującego identyfikator na widok, liczy pełne wyprowadzanie klucza i przez to trwa dłużej.

## Wywołanie

Z PowerShell: `.\www\tests\e2e-view.ps1`. Skrypt startuje własny serwer PHP z routerem i katalogiem danych w miejscu tymczasowym. Wymaga PHP CLI i przeglądarki opartej na Chromium; wyjście zerowe oznacza komplet zielonych przypadków.

## Kiedy odpalać

Ręcznie po zmianach w widoku (formularz hasła, odszyfrowanie formatu trzeciego, zapytanie wewnętrzne) albo w `crypto.js`.

## Nie sprawdza

Nie powtarza tego, co pokrywa główna suita `www/tests/run.ps1`, i nie zastępuje jej - bada wyłącznie wymienione ścieżki widoku. Nie sprawdza produkcji ani parytetu kryptografii ze złotym wektorem. Nie sprawdza zachowania w przeglądarkach spoza rodziny Chromium.

## Kotwice

Wynik przestaje znaczyć, gdy zniknie router `tests/e2e-router.php`, bo to on daje ścieżkę z identyfikatorem prowadzącą do widoku - główna suita takiego routera nie ma. Zależy od tego, że przekierowanie katalogu danych robi `tests/bootstrap.php` doładowywany przed każdym żądaniem. Wyprowadzanie klucza liczy się naprawdę, więc czas przebiegu zależy od liczby iteracji przyjętej w kryptografii; domyślny limit czasu jest parametrem skryptu. Domyślna ścieżka PHP, lista miejsc, w których szuka przeglądarki, i pula portów są wpisane w kod. Sprzątanie drzewa procesów przeglądarki rozpoznaje procesy po unikatowym katalogu profilu, po nazwach plików wykonywalnych Chrome i Edge.
