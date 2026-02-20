<?php
/**
 * i18n — PL/EN z Accept-Language
 */

function detect_lang(): string {
    $header = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
    if (stripos($header, 'pl') !== false) return 'pl';
    return 'en';
}

function get_strings(string $lang = null): array {
    if ($lang === null) $lang = detect_lang();

    $strings = [
        'pl' => [
            'title' => defined('APP_NAME') ? APP_NAME : 'bitback.one',
            'subtitle' => 'bezpieczne jednorazowe linki',
            'content_label' => 'Treść',
            'placeholder_line1' => 'Wpisz treść tutaj...',
            'placeholder_line2' => 'zaznacz fragment i naciśnij Ctrl+E aby oznaczyć jako poufne',
            'placeholder_line3' => 'ponowne Ctrl+E na poufnym fragmencie — odznacza',
            'settings_label' => 'Ustawienia',
            'expire_label' => 'Wygaśnięcie danych poufnych',
            'expire_unit' => 'dni',
            'views_label' => 'Maksymalna liczba wyświetleń',
            'views_unit' => 'razy',
            'delete_label' => 'Permanentne usunięcie po',
            'delete_unit' => 'dni (0 = od razu)',
            'verify_label' => 'Weryfikacja',
            'generate_btn' => 'Generuj link',
            'your_link' => 'Twój link',
            'copy' => 'Kopiuj',
            'copied' => 'Skopiowano!',
            'preview_label' => 'Podgląd',
            'preview_expired' => 'po wygaśnięciu',
            'preview_active' => 'aktywny link',
            'error_empty' => 'Wpisz treść.',
            'error_math' => 'Nieprawidłowa odpowiedź.',
            'error_bot' => 'Błąd weryfikacji.',
            'error_ratelimit' => 'Zbyt wiele prób. Spróbuj później.',
            'error_server' => 'Błąd serwera. Spróbuj ponownie.',
            // strona odczytu
            'secrets_expired' => 'Dane poufne wygasły',
            'secrets_expired_info' => 'Poufne fragmenty zostały trwale zamaskowane.',
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
            'your_password' => 'Twoje hasło:',
            // licznik permanentnego usunięcia
            'delete_permanent_in' => 'dni do usunięcia',
            'delete_permanent_label' => 'Permanentne usunięcie:',
            'delete_permanent_today' => 'Usunięcie wkrótce',
        ],
        'en' => [
            'title' => defined('APP_NAME') ? APP_NAME : 'bitback.one',
            'subtitle' => 'secure one-time links',
            'content_label' => 'Content',
            'placeholder_line1' => 'Type your content here...',
            'placeholder_line2' => 'select text and press Ctrl+E to mark as secret',
            'placeholder_line3' => 'press Ctrl+E again on a secret to unmark it',
            'settings_label' => 'Settings',
            'expire_label' => 'Secret data expiration',
            'expire_unit' => 'days',
            'views_label' => 'Maximum views',
            'views_unit' => 'times',
            'delete_label' => 'Permanent deletion after',
            'delete_unit' => 'days (0 = immediately)',
            'verify_label' => 'Verification',
            'generate_btn' => 'Generate link',
            'your_link' => 'Your link',
            'copy' => 'Copy',
            'copied' => 'Copied!',
            'preview_label' => 'Preview',
            'preview_expired' => 'after expiry',
            'preview_active' => 'active link',
            'error_empty' => 'Enter some content.',
            'error_math' => 'Wrong answer.',
            'error_bot' => 'Verification failed.',
            'error_ratelimit' => 'Too many attempts. Try later.',
            'error_server' => 'Server error. Try again.',
            'secrets_expired' => 'Secret data has expired',
            'secrets_expired_info' => 'Confidential fragments have been permanently masked.',
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
            'your_password' => 'Your password:',
            // permanent deletion countdown
            'delete_permanent_in' => 'days to deletion',
            'delete_permanent_label' => 'Permanent deletion:',
            'delete_permanent_today' => 'Deletion imminent',
        ],
    ];

    return $strings[$lang] ?? $strings['en'];
}
