# www/tools/gen-api-token.php

## Po co

Generuje token API dla integratora i drukuje trzy rzeczy (w trybie `--save-bb` dwie, bez tokena): pełny token do wręczenia osobie (widoczny raz, nieodtwarzalny), jawny identyfikator do zmapowania osoby na token w lokalnej dokumentacji oraz gotową linię do wklejenia do pliku uwierzytelniania na serwerze. Plik serwera trzyma wyłącznie parę identyfikator plus skrót sekretu, bez imion - imiona w pliku uwierzytelniania ujawniałyby, kto ma dostęp, więc wyciek pliku byłby mapą tożsamości. Mapowanie osoby na identyfikator żyje osobno, poza serwerem. Odwołanie tokena to skasowanie jego linii, niezależnie od pozostałych.

## Wywołanie

Z korzenia kodu aplikacji: `php tools/gen-api-token.php ["nazwa dla własnej referencji"]`. Wyłącznie z linii poleceń - wywołanie przez serwer WWW kończy się odmową. Nazwa jest opcjonalna i trafia tylko na wydruk, nigdy do pliku serwera.

Tryb dla sesji AI, bez wydruku tokena: `php tools/gen-api-token.php --save-bb <klucz-bb-cs> ["nazwa"]`. Token trafia prosto do `bb cs save <klucz>` (typ generic), a na wydruk idą tylko jawny identyfikator i linia do pliku serwera. Wymaga `bb` w PATH; przy błędzie zapisu kończy kodem niezerowym i nic nie drukuje z tokena.

## Kiedy odpalać

Kiedy nowy integrator ma dostać dostęp do API. Uruchamiane rzadko i ręcznie.

## Nie sprawdza

Nie dotyczy (generator). Sam niczego nie zapisuje: linię do pliku uwierzytelniania trzeba wkleić ręcznie, więc wygenerowanie tokena nie oznacza jeszcze, że działa. Nie sprawdza, czy identyfikator już w pliku występuje, i nie odwołuje starych tokenów.

## Kotwice

Wynik przestaje znaczyć, gdy zmieni się format pliku uwierzytelniania `inc/api-tokens.txt` (oczekiwany: identyfikator, odstęp, skrót sekretu) albo sposób weryfikacji po stronie API. Kształt tokena jest wpisany w kod: przedrostek `bbk_`, ośmioznakowy identyfikator szesnastkowy i sekret o długości dwustu pięćdziesięciu sześciu bitów w zapisie base64 bezpiecznym dla adresów, a w pliku ląduje skrót SHA-256 samego sekretu - zmiana którejkolwiek z tych decyzji po stronie serwera rozjeżdża generator z weryfikacją. Wdrożenie chroni ten plik przed nadpisaniem i pilnuje, żeby po synchronizacji nie był pusty.
