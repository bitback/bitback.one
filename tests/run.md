# www/tests/run.ps1

## Po co

Główna suita testów projektu. Startuje własny serwer PHP z wyłączonym wypisywaniem błędów na wolnym porcie, żeby kody HTTP były przewidywalne (ostrzeżenie wyciekające do odpowiedzi psuje status), i przepuszcza aplikację przez cztery filary: przeglądarkę, punkty końcowe, funkcje czyste PHP i zadanie sprzątające. Filar przeglądarkowy renderuje harness, który ładuje realny `index.php` w ramce i woła prawdziwe funkcje aplikacji - bez kopii kodu, więc test nie dryfuje wobec produktu. Werdykt zbiorczy jest zielony tylko wtedy, gdy zielone są wszystkie cztery filary, a filar przeglądarkowy w ogóle zameldował jakikolwiek wynik.

## Wywołanie

Z PowerShell (5.1 albo 7): `.\www\tests\run.ps1`. Skrypt sam wystawia serwer z katalogu o poziom wyżej niż `tests\`, więc działa też odpalony z kopii na dysku produkcyjnym. Wymaga PHP CLI i przeglądarki opartej na Chromium (Chrome albo Edge); ścieżkę PHP nadpisuje `$env:BB_PHP`, przeglądarkę `$env:BB_BROWSER`. Zrzut ekranu suity przeglądarkowej ląduje w `tests/output/suite.png`.

## Kiedy odpalać

Po każdej zmianie w kodzie aplikacji, zanim commit pojedzie na produkcję - wdrożenie tej suity nie woła. Testy pracują na własnym katalogu danych w miejscu tymczasowym (repozytoryjne `data/` trzyma realne rekordy i jest tylko do odczytu), więc przebieg jest bezpieczny dla danych.

## Nie sprawdza

Nie pokrywa ścieżek widoku wyniesionych do `www/tests/e2e-view.ps1` (formularz hasła, zapytanie wewnętrzne przy braku klucza nadrzędnego, uszkodzony fragment adresu, link bez hasła) - filar przeglądarkowy nie ma routera przekierowującego identyfikator na widok. Nie sprawdza wersji angielskiej (to `www/tests/verify-en.ps1`) ani parytetu kryptografii ze złotym wektorem (to `interop/gen/verify-vectors.mjs`). Nie sprawdza produkcji - wszystko dzieje się na serwerze lokalnym. Zrzut PNG jest wyłącznie diagnostyczny i bywa niepełny, więc nie jest dowodem na nic.

## Kotwice

Wynik przestaje znaczyć, gdy harness przestanie meldować wynik do `tests/collect.php` - momentu zakończenia suity nie da się obstawić czasem, bo zrzut modelu dokumentu bywa martwy w danym wydaniu przeglądarki (zwraca zero bajtów bez błędu), a budżet czasu wirtualnego odmierza czas wirtualny i wygasa w trakcie realnego liczenia funkcji wyprowadzania klucza, ucinając suitę w losowym miejscu. Zależy od formatu meldunku (pierwsza linia `PASS`/`FAIL` z liczbą przypadków) i od kodów wyjścia trzech skryptów potomnych. Domyślna ścieżka PHP i pula portów są wpisane w kod. Filar funkcji czystych wymaga jawnego doładowania rozszerzenia openssl, bo ten PHP startuje bez pliku konfiguracyjnego - inaczej testy starszego trybu szyfrowania same oznaczą się jako pominięte. Sprzątanie drzewa procesów przeglądarki rozpoznaje procesy po unikatowym katalogu profilu; zmiana nazw plików wykonywalnych przeglądarek zostawia procesy w tle.
