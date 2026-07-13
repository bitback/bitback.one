<?php
/**
 * Router dla wbudowanego serwera PHP (php -S) na czas E2E widoku.
 * Odtwarza produkcyjny rewrite /uuid -> view.php?slug=uuid (Apache robi to przez
 * .htaccess, ktorego php -S nie czyta). Reszta requestow idzie normalnie.
 * Uzywany tylko przez tests/e2e-view.ps1.
 */
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$slug = ltrim($uri, '/');
if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $slug)) {
    $_GET['slug'] = $slug;
    require dirname(__DIR__) . '/view.php';
    return true;
}
return false;
