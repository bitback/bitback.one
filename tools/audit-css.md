# www/tools/audit-css.php

## Po co

Odpowiada na pytanie, co w arkuszach jest martwe i ile wagi zjada warstwa dekoracyjna. Przy upraszczaniu wyglądu trzeba wiedzieć, które reguły wolno skasować bez ryzyka, a które tylko wyglądają na nieużywane, bo dotyczą stanu pojawiającego się dopiero po interakcji (wynik generowania, wklejona tabela, oznaczony sekret) - przeglądarkowe wyliczanie nieużywanego CSS tego nie rozróżnia. Klasa jest uznana za martwą, gdy jej nazwa nie występuje w żadnym źródle, które może ją nadać: w szablonach PHP ani w skryptach. Szukana jest sama nazwa, nie atrybut klasy, bo klasy bywają nadawane dynamicznie. Raport ma trzy części: martwe klasy per arkusz, stan zmiennych z pliku tokenów (ile zadeklarowanych, ile różnych wartości, nieużywane, użyte dokładnie raz, grupy o identycznej wartości) i skalę warstwy dekoracyjnej liczoną wystąpieniami wybranych cech.

## Wywołanie

Z korzenia kodu aplikacji: `php tools/audit-css.php`. Raport idzie na wyjście standardowe, narzędzie niczego nie zapisuje.

## Kiedy odpalać

Przed decyzją o kasowaniu reguł i przed upraszczaniem wyglądu, oraz po większej przebudowie stylów, kiedy trzeba zobaczyć, ile z nowej warstwy dekoracyjnej faktycznie przybyło.

## Nie sprawdza

Nie sprawdza poprawności składni arkuszy ani tego, czy strona wygląda dobrze. Nie rozstrzyga, czy klasa jest naprawdę osiągalna - mówi tylko, że jej nazwa gdzieś w źródłach pada, więc nazwa użyta wyłącznie w martwym kodzie liczy się jako żywa. Odwrotnie też: nazwa sklejana z kawałków w czasie działania nie zostanie znaleziona i wyjdzie jako fałszywy alarm. Skala warstwy dekoracyjnej to liczba wystąpień wzorców, nie miara wpływu na wygląd czy wydajność. Kolorów nie dotyka - to `www/tools/audit-colors.php`.

## Kotwice

Wynik przestaje znaczyć, gdy zmieni się rozmieszczenie plików wpisane w kod: arkusze brane są z `assets/css/` i `assets/`, źródła nadające klasy z plików PHP w korzeniu, `inc/` i `api/` oraz ze skryptów w `assets/js/` i w korzeniu, a zmienne z `assets/tokens.css`. Nowy katalog z szablonami albo skryptami poza tą listą zamieni żywe klasy w martwe na raporcie. Nazwy zmiennych rozpoznawane są po przedrostku `--bb-`, a lista cech warstwy dekoracyjnej jest wpisana w kod razem z nazwami klas projektowych - zmiana konwencji nazewniczej wymaga poprawki narzędzia.
