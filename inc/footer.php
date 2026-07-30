<?php
/**
 * Stopka serwisu, jedno zrodlo dla wszystkich stron.
 *
 * Byla wklejona 8 razy: raz jako klasa .site-footer (trzy widoki) i siedem razy
 * jako recznie powtorzone atrybuty style, bajt w bajt takie same. Nota o
 * licencji jest wymagana na kazdej stronie, wiec rozjazd kopii przy zmianie
 * tresci byl realny - i raz juz sie zdarzyl (view_footer_html mial zaszyte
 * literaly PL i omijal zmiane noty w i18n).
 *
 * Dwa warianty roznia sie WYLACZNIE zakresem danych kontaktowych:
 * pelny na stronach tresci, skrocony na stronach przejsciowych (bramka hasla,
 * 404, wygasniecie), gdzie stopka ma nie przykrywac komunikatu.
 */

function site_footer_html(bool $compact = false): string {
    $t = get_strings(detect_lang());
    $s = '<span class="sep">|</span>';

    $html = '<div class="site-footer' . ($compact ? ' compact' : '') . '">'
        . '<a href="https://bitback.pl" target="_blank" rel="noopener"><strong>bitback.pl</strong></a>';

    if (!$compact) {
        $html .= $s . htmlspecialchars($t['footer_tagline'])
            . $s . 'Zbigniew Gralewski'
            . $s . '<a href="mailto:zbigniew.gralewski@bitback.pl">zbigniew.gralewski@bitback.pl</a>'
            . $s . '609 505 065';
    }

    $html .= $s . htmlspecialchars($t['footer_source'])
        . ' <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener">GitHub</a>'
        . $s . '<strong class="commercial">' . htmlspecialchars($t['footer_commercial']) . '</strong>'
        . '</div>';

    return $html;
}
