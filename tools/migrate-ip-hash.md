# www/tools/migrate-ip-hash.php

## Po co

Jednorazowa migracja prywatności: zamienia surowe adresy IP w dzienniku odsłon rekordu na skróty. Każdy wpis dziennika z polem adresu dostaje w zamian dwunastoznakowy początek skrótu SHA-256 policzonego z adresu i soli, a samo pole adresu znika. Migracja obejmuje rekordy bieżące i te leżące w koszu.

## Wywołanie

Z korzenia kodu aplikacji, tam gdzie leżą dane: `php tools/migrate-ip-hash.php`. Przebieg nadpisuje pliki rekordów w miejscu.

## Kiedy odpalać

Nie ustalone z kodu.

## Nie sprawdza

Nie dotyczy (migracja). Warto wiedzieć, czego nie robi: nie tworzy kopii zapasowej przed nadpisaniem pliku, nie da się jej cofnąć (skrót jest jednokierunkowy) i nie ma trybu próbnego. Rekordy bez dziennika odsłon oraz pliki, których nie da się odczytać jako JSON, są po cichu liczone jako pominięte; podsumowanie podaje same liczby zmigrowanych, pominiętych i błędnych, bez rozróżnienia powodu pominięcia.

## Kotwice

Wynik przestaje znaczyć, gdy zmieni się kształt rekordu: nazwy pól `view_log`, `ip` i `ip_hash` są wpisane w kod, podobnie jak długość skracanego skrótu. Sól brana jest ze stałej `IP_HASH_SALT` w `inc/config.php`, a w repozytorium leży pod nią atrapa - uruchomienie na kopii z atrapą wyprodukuje skróty niezgodne z produkcją. Katalogi rekordów i kosza czytane są ze stałych `DATA_DIR` i `TRASH_DIR`; przeniesienie danych gdzie indziej zmienia to, co narzędzie w ogóle zobaczy.
