<?php
/**
 * i18n — PL/EN z Accept-Language
 */

function detect_lang(): string {
    // Override przez querystring ?lang=en lub ?lang=pl - uzyteczne do testowania
    // i dla userow ktorzy chca wymusic jezyk. Dzialanie: ?lang=en przed # w URL.
    if (isset($_GET['lang']) && in_array($_GET['lang'], ['pl', 'en'], true)) {
        return $_GET['lang'];
    }
    $header = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
    if (stripos($header, 'pl') !== false) return 'pl';
    return 'en';
}

function get_strings(?string $lang = null): array {
    if ($lang === null) $lang = detect_lang();

    $strings = [
        'pl' => [
            'title' => defined('APP_NAME') ? APP_NAME : 'bitback.one',
            'subtitle' => 'bezpieczne linki do przekazywania poufnych danych',
            'content_label' => 'Treść',
            'placeholder_line1' => 'Wpisz treść tutaj...',
            'placeholder_line2' => 'zaznacz fragment i naciśnij Ctrl+E aby oznaczyć jako poufne',
            'placeholder_line3' => 'ponowne Ctrl+E na poufnym fragmencie — odznacza',
            'settings_label' => 'Ustawienia',
            'optional_tag' => 'opcjonalnie',
            'expire_label' => 'Wygaśnięcie danych poufnych',
            'expire_unit' => 'dni',
            'views_label' => 'Maksymalna liczba wyświetleń',
            'views_unit' => 'razy',
            'delete_label' => 'Permanentne usunięcie po',
            'delete_unit' => 'dni (0 = od razu)',
            'verify_label' => 'Weryfikacja',
            'generate_label' => 'Wygeneruj link',
            'generate_btn' => 'Generuj link',
            'generating' => 'Szyfrowanie...',
            'your_link' => 'Twój link',
            'copy' => 'Kopiuj',
            'copied' => 'Skopiowano!',
            'preview_label' => 'Podgląd',
            'preview_expired' => 'po wygaśnięciu',
            'preview_empty' => 'Tu pojawi się podgląd po wpisaniu treści.',
            'error_empty' => 'Wpisz treść.',
            'error_math' => 'Nieprawidłowa odpowiedź.',
            'error_bot' => 'Błąd weryfikacji.',
            'error_ratelimit' => 'Zbyt wiele prób. Spróbuj później.',
            'error_server' => 'Błąd serwera. Spróbuj ponownie.',
            // strona odczytu
            'secrets_expired' => 'Dane poufne wygasły',
            'secrets_expired_info' => 'Poufne fragmenty zostały trwale zamaskowane.',
            'totp_qr_title' => 'Kod TOTP - zeskanuj w aplikacji uwierzytelniającej',
            'link_expired' => 'Ten link wygasł',
            'link_expired_info' => 'Udostępnione dane zostały usunięte.',
            'views_count' => 'wyświetleń',
            'expires_on' => 'Wygaśnięcie:',
            'days_left' => 'dni do wygaśnięcia',
            'views_left' => 'pozostałych wyświetleń',
            // hasło
            'password_label' => 'Hasło otwarcia (opcjonalne)',
            'password_placeholder_config' => 'zostaw puste = bez hasła',
            'password_required' => 'Ten link jest chroniony hasłem',
            'password_placeholder' => 'Wpisz hasło',
            'password_submit' => 'Otwórz',
            'password_wrong' => 'Nieprawidłowe hasło.',
            'password_too_many' => 'Zbyt wiele nieudanych prób. Spróbuj ponownie za godzinę.',
            'your_password' => 'Twoje hasło:',
            'password_checking' => 'Sprawdzanie hasła...',
            'password_wrong_or_corrupt' => 'Nieprawidłowe hasło lub uszkodzony link.',
            'password_js_required' => 'Do otwarcia linku z hasłem wymagany jest JavaScript.',
            'password_reenter' => 'Podaj hasło, aby odszyfrować dane',
            'password_unrecoverable' => 'Hasła nie da się odzyskać. Zapisz je przed wysłaniem linku.',
            'password_generate' => 'Generuj',
            'deriving_keys' => 'Szyfrowanie...',
            // licznik permanentnego usunięcia
            'delete_permanent_in' => 'dni do usunięcia',
            'delete_permanent_label' => 'Permanentne usunięcie:',
            'delete_permanent_today' => 'Usunięcie wkrótce',
            // 404
            'not_found_title' => 'Nie ma takiego linka',
            'not_found_sub' => 'Albo nigdy nie istniał, albo został permanentnie usunięty.',
            'not_found_hint' => 'Sprawdź czy link jest kompletny — klucz deszyfrujący jest za znakiem #',
            // index: meta / OG
            'meta_title' => 'bitback.one - bezpieczne udostępnianie danych',
            'og_description' => 'Bezpieczne jednorazowe linki do przekazywania poufnych danych. Szyfrowanie AES-256 w przeglądarce, zero-trust - serwer nigdy nie widzi treści.',
            // view: OG
            'og_view_title' => 'Bezpieczna wiadomość - bitback.one',
            'og_view_description' => 'Ktoś udostępnił Ci poufne dane przez zaszyfrowany link jednorazowy.',
            // index: trust bar
            'security_label' => 'Bezpieczeństwo',
            'security_p1' => 'Wstępnie stworzyliśmy bitback.one dla siebie, aby przesyłać dane logowania naszym Klientom. Aplikacja została otwarta do ogólnego użytku.',
            'security_p2' => '<strong>Bitback.one zapewnia 100% poufności przekazywanych danych.</strong> Jest stworzony w modelu ZERO TRUST, czyli nie ufa serwerowi ani infrastrukturze. Dane szyfruje Twoja przeglądarka i trafiają na serwer w formie już zaszyfrowanej. Unikalny link przypisany do Twoich danych jest od razu kluczem deszyfrującym. Kto ma link, ten może odszyfrować dane. Zauważ, że link zawiera znak „#”, a część linku po tym znaku nigdy nie trafia do serwera (tak działa protokół HTTP). Skrypty są przypięte skrótem kryptograficznym, więc przeglądarka odmówi uruchomienia podmienionego kodu. Kod źródłowy aplikacji jest otwarty i zapewnia pełną audytowalność.',
            'security_p3' => '<strong>Używasz bitback.one następująco:</strong> wypełniasz pole treści. Oznaczasz dane poufne, weryfikujesz się, generujesz link. Kopiujesz link do schowka i przekazujesz go np. emailem właściwej osobie. Ta osoba po odbiorze może wygasić lub usunąć link. Wygaszenie powoduje, że część danych (ta poufna) zostaje zamazana do czasu pełnego usunięcia linku - zwykle dłużej, np. po roku. Przez ten czas widać, co zostało wysłane, ale dane poufne po zamazaniu są już nie do odzyskania.',
            'security_p4' => '<strong>Dlaczego bitback.one?</strong> Ponieważ inne aplikacje bazują na wygaszaniu całej treści - link wygasa i nie jesteś w stanie stwierdzić, co zostało komuś wysłane. Masz w mailu link, który nie działa. Bitback.one rozwiązuje ten problem. Pozwala wygaszać dane stopniowo. Najpierw wygaszasz tylko część poufną, a reszta jest czytelna pod warunkiem posiadania linku. Później można usunąć cały link. Stopniowe wygaszanie jest praktyczne, bo część opisowa jest wciąż czytelna do czasu permanentnego usunięcia całości.',
            'security_p5' => '<strong>Autorem bitback.one</strong> jest Zbigniew Gralewski, właściciel bitback.pl - dostawcy zabezpieczeń dla firm i organizacji.',
            // index: hint bar
            'hint_text' => 'Wpisz treść poniżej. Oznacz fragmenty <strong class="hl">poufne</strong> (przycisk lub <span class="kbd-chip">Ctrl+E</span>).',
            'mark_note' => 'Poufne fragmenty zostaną bezpowrotnie zamazane po wygaśnięciu linka. Link działa do czasu jego permanentnego usunięcia.',
            'mark_secret_btn' => 'Oznacz zaznaczony tekst jako poufny',
            // index: editor placeholder
            'editor_placeholder' => "Wpisz treść tutaj...\nNp. Login: admin\nHasło: s3cret123  ← zaznacz i Ctrl+E",
            // index: JS alerts/messages
            'error_math_select' => 'Wybierz odpowiedź na pytanie.',
            'error_connection' => 'Błąd połączenia z serwerem.',
            // index: import tabeli (bulk)
            'import_detected' => 'Tabela rozpoznana: {rows} wierszy, {cols} kolumn',
            'import_multi_tables' => 'Wykryto {n} tabel - użyto pierwszej, pozostałe pominięto',
            'plain_text_toggle' => 'Traktuj tabelę jako zwykły tekst',
            'bulk_preview_note' => 'Podgląd 1. rekordu z {n} (tak zobaczy odbiorca)',
            'error_batch_too_many' => 'Za dużo osób w paczce (maksymalnie {max}). Zmniejsz tabelę.',
            'error_batch' => 'Paczka jest za duża. Zmniejsz liczbę osób lub rozmiar danych.',
            // index: footer
            'footer_tagline' => 'Zabezpieczamy pocztę, serwery i komputery',
            'footer_source' => 'Kod źródłowy na',
            'footer_commercial' => 'Kod na licencji AGPL, wersja komercyjna dostępna',
        ],
        'en' => [
            'title' => defined('APP_NAME') ? APP_NAME : 'bitback.one',
            'subtitle' => 'secure links for sharing confidential data',
            'content_label' => 'Content',
            'placeholder_line1' => 'Type your content here...',
            'placeholder_line2' => 'select text and press Ctrl+E to mark as secret',
            'placeholder_line3' => 'press Ctrl+E again on a secret to unmark it',
            'settings_label' => 'Settings',
            'optional_tag' => 'optional',
            'expire_label' => 'Secret data expiration',
            'expire_unit' => 'days',
            'views_label' => 'Maximum views',
            'views_unit' => 'times',
            'delete_label' => 'Permanent deletion after',
            'delete_unit' => 'days (0 = immediately)',
            'verify_label' => 'Verification',
            'generate_label' => 'Generate link',
            'generate_btn' => 'Generate link',
            'generating' => 'Encrypting...',
            'your_link' => 'Your link',
            'copy' => 'Copy',
            'copied' => 'Copied!',
            'preview_label' => 'Preview',
            'preview_expired' => 'after expiry',
            'preview_empty' => 'Preview will appear here once you type content.',
            'error_empty' => 'Enter some content.',
            'error_math' => 'Wrong answer.',
            'error_bot' => 'Verification failed.',
            'error_ratelimit' => 'Too many attempts. Try later.',
            'error_server' => 'Server error. Try again.',
            'secrets_expired' => 'Secret data has expired',
            'secrets_expired_info' => 'Confidential fragments have been permanently masked.',
            'totp_qr_title' => 'TOTP code - scan it in your authenticator app',
            'link_expired' => 'This link has expired',
            'link_expired_info' => 'The shared data has been deleted.',
            'views_count' => 'views',
            'expires_on' => 'Expires:',
            'days_left' => 'days remaining',
            'views_left' => 'views remaining',
            // password
            'password_label' => 'Open password (optional)',
            'password_placeholder_config' => 'leave empty = no password',
            'password_required' => 'This link is password protected',
            'password_placeholder' => 'Enter password',
            'password_submit' => 'Open',
            'password_wrong' => 'Wrong password.',
            'password_too_many' => 'Too many failed attempts. Try again in an hour.',
            'your_password' => 'Your password:',
            'password_checking' => 'Checking password...',
            'password_wrong_or_corrupt' => 'Wrong password or corrupted link.',
            'password_js_required' => 'JavaScript is required to open a password-protected link.',
            'password_reenter' => 'Enter the password to decrypt the data',
            'password_unrecoverable' => 'The password cannot be recovered. Save it before sending the link.',
            'password_generate' => 'Generate',
            'deriving_keys' => 'Encrypting...',
            // permanent deletion countdown
            'delete_permanent_in' => 'days to deletion',
            'delete_permanent_label' => 'Permanent deletion:',
            'delete_permanent_today' => 'Deletion imminent',
            // 404
            'not_found_title' => 'This link does not exist',
            'not_found_sub' => 'It either never existed or has been permanently deleted.',
            'not_found_hint' => 'Make sure the link is complete — the decryption key is after the # sign',
            // index: meta / OG
            'meta_title' => 'bitback.one - secure data sharing',
            'og_description' => 'Secure one-time links for sharing sensitive data. AES-256 encryption in the browser, zero-trust - the server never sees your content.',
            // view: OG
            'og_view_title' => 'Secure message - bitback.one',
            'og_view_description' => 'Someone shared sensitive data with you through an encrypted one-time link.',
            // index: trust bar
            'security_label' => 'Security',
            'security_p1' => 'We originally built bitback.one for ourselves, to send login details to our clients. The application has since been opened for general use.',
            'security_p2' => '<strong>Bitback.one keeps the data you send fully confidential.</strong> It is built on the ZERO TRUST model, which means it trusts neither the server nor the infrastructure. Your browser encrypts the data and it reaches the server already encrypted. The unique link tied to your data is also the decryption key. Whoever has the link can decrypt the data. Note that the link contains a "#" character, and the part after it never reaches the server (that is how the HTTP protocol works). The scripts are pinned with a cryptographic hash, so the browser refuses to run code that has been swapped. The source code of the application is open, which makes it fully auditable.',
            'security_p3' => '<strong>You use bitback.one like this:</strong> fill in the content field. Mark the confidential data, pass the verification, generate the link. Copy the link and pass it to the right person, for example by email. Once they have it, they can expire or delete the link. Expiring blanks out the confidential part until the whole link is deleted, which usually happens much later, for example after a year. Until then it stays visible what was sent, but confidential data, once blanked out, cannot be recovered.',
            'security_p4' => '<strong>Why bitback.one?</strong> Because other applications expire the whole content - the link dies and you can no longer tell what you sent to whom. You are left with a dead link in your mailbox. Bitback.one solves this by expiring data in stages. First only the confidential part is blanked out, while the rest stays readable to whoever has the link. Later the whole link can be deleted. Staged expiry is practical, because the descriptive part stays readable until everything is permanently removed.',
            'security_p5' => '<strong>bitback.one was created by</strong> Zbigniew Gralewski, owner of bitback.pl, a security provider for companies and organisations.',
            // index: hint bar
            'hint_text' => 'Type your content below. Mark the <strong class="hl">secret</strong> fragments (button or <span class="kbd-chip">Ctrl+E</span>).',
            'mark_note' => 'Secret fragments are irreversibly wiped after the link expires. The link works until it is permanently deleted.',
            'mark_secret_btn' => 'Mark selected text as secret',
            // index: editor placeholder
            'editor_placeholder' => "Type your content here...\ne.g. Login: admin\nPassword: s3cret123  ← select and Ctrl+E",
            // index: JS alerts/messages
            'error_math_select' => 'Select an answer to the question.',
            'error_connection' => 'Connection error.',
            // index: import tabeli (bulk)
            'import_detected' => 'Table detected: {rows} rows, {cols} columns',
            'import_multi_tables' => 'Detected {n} tables - used the first, rest skipped',
            'plain_text_toggle' => 'Treat table as plain text',
            'bulk_preview_note' => 'Preview of record 1 of {n} (as the recipient sees it)',
            'error_batch_too_many' => 'Too many people in the batch (max {max}). Reduce the table.',
            'error_batch' => 'The batch is too large. Reduce the number of people or data size.',
            // index: footer
            'footer_tagline' => 'We secure email, servers and computers',
            'footer_source' => 'Source code on',
            'footer_commercial' => 'AGPL-licensed, commercial license available',
        ],
    ];

    return $strings[$lang] ?? $strings['en'];
}
