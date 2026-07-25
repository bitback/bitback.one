<?php
/**
 * Wspolne prymitywy uzywane przez wiecej niz jeden endpoint.
 *
 * Wczesniej safe_host() i save_locked() istnialy jako doslowne kopie w kilku
 * plikach. Oba sa istotne dla bezpieczenstwa/spojnosci (guard na header
 * injection oraz atomowy zapis pod trzymanym lockiem), wiec rozjazd kopii przy
 * poprawce w jednym miejscu bylby realnym ryzykiem.
 */

/**
 * Host do generowanych URL-i. HTTP_HOST jest kontrolowany przez klienta
 * (header injection / phishing) - przyjmujemy tylko poprawny hostname[:port],
 * inaczej fallback do SERVER_NAME. APP_HOST w config.php wymusza na sztywno.
 */
if (!function_exists('safe_host')) {
    function safe_host(): string {
        if (defined('APP_HOST') && APP_HOST !== '') {
            return APP_HOST;
        }
        $host = $_SERVER['HTTP_HOST'] ?? '';
        if (preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:\d{1,5})?$/', $host)) {
            return $host;
        }
        return $_SERVER['SERVER_NAME'] ?? 'localhost';
    }
}

/** Schemat zadania (https gdy TLS). */
if (!function_exists('request_scheme')) {
    function request_scheme(): string {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    }
}

/**
 * Zapis rekordu pod JUZ trzymanym lockiem (nadpisanie w miejscu).
 * Wolajacy odpowiada za fopen('r+') + flock(LOCK_EX) i za fclose().
 */
if (!function_exists('save_locked')) {
    function save_locked($fp, array $data): void {
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        rewind($fp);
        ftruncate($fp, 0);
        fwrite($fp, $json);
        fflush($fp);
    }
}
