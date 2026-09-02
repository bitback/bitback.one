# www/tools/audit-colors.php

## Po co

Zbiera wszystkie kolory ze wszystkich źródeł, przelicza je na HSL i grupuje po odcieniu. Stoi na założeniu, że "za dużo zielonych" to nie kwestia gustu, tylko mierzalny fakt: dwa zielone o różnym nasyceniu czytają się jako dwa niespokrewnione kolory. Dlatego narzędzie pokazuje rozrzut nasycenia i jasności w obrębie jednego odcienia - to on odpowiada za wrażenie bałaganu, nie sama liczba odcieni. Parsuje każdą notację koloru CSS (zapis szesnastkowy w czterech długościach, `rgb`/`rgba`, `hsl`/`hsla` w obu składniach separatorów, nazwy kolorów) i rozwiązuje odwołania do tokenów, bo paleta projektu jest zapisana w `hsl()` z kompozycją tokenów. Odcień neutralny czytany z tokenów jest traktowany osobno: powierzchnie, tekst i ramki stoją na nim celowo i mają szeroki rozrzut nasycenia, więc bez tego wyjątku alarm dzwoniłby na stałe i przestałby cokolwiek znaczyć.

## Wywołanie

Z korzenia kodu aplikacji: `php tools/audit-colors.php`. Raport idzie na wyjście standardowe, narzędzie niczego nie zapisuje.

## Kiedy odpalać

Przy porządkowaniu palety i po dołożeniu kolorów, kiedy trzeba sprawdzić, czy nowe wartości nie rozjeżdżają odcieni już używanych.

## Nie sprawdza

Świadomie poza zakresem: kolory rysowane w czasie działania przez bibliotekę kodu QR (rysunek na płótnie, czerń i biel), kolory systemowe przeglądarki oraz nazwy kolorów użyte w komentarzach. Skan pomija katalogi, które z definicji nie należą do palety interfejsu: testy (atrapy i znaczniki), narzędzia (mają własne tablice barw), dane bieżące i kosz - ta granica jest wypisywana w wyniku, żeby nie była cichym założeniem. Narzędzie nie ocenia kontrastu ani dostępności, nie mówi, który kolor jest właściwy, i nie zmienia niczego w arkuszach.

## Kotwice

Narzędzie samo sprawdza swoje kotwice przy każdym uruchomieniu i wypisuje instrukcję, gdy któraś się rozjedzie. Pilnuje trzech rzeczy: że `assets/tokens.css` nadal jest źródłem palety, że notacja palety w tokenach to nadal `hsl` (przejście na `oklch` albo `color()` oślepia parser i wymaga jego rozszerzenia) i że katalog arkuszy `assets/css` nadal istnieje. Poza tym skan obejmuje wyłącznie pliki o rozszerzeniach `css`, `php`, `js`, `svg` i `html` - nowy typ pliku niosącego style wypada z zakresu po cichu i jest powodem do ponownego audytu zakresu. Odcień neutralny czytany jest ze zmiennej `--bb-h-neutral`; zmiana konwencji nazewniczej tokenów rozbraja wyjątek dla powierzchni.
