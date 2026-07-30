// Podlaczenie zdarzen strony glownej. Wczesniej siedzialo w atrybutach on* w
// HTML; teraz HTML jest czystym dokumentem, a intencja przycisku opisuje
// atrybut data-bb-action. Dzieki temu strona nie ma ANI JEDNEGO wykonywalnego
// fragmentu JS, wiec da sie ja kiedys objac CSP bez 'unsafe-inline'.
//
// Delegacja na document, a nie listener per przycisk: podglad i wyniki bulk
// dostawiaja elementy dynamicznie, wiec wiazanie po nazwie w momencie startu
// pomijaloby wszystko, co powstanie pozniej.
//
// Ten plik laduje sie OSTATNI - wolane funkcje musza byc juz zdefiniowane.

document.addEventListener('click', function(ev) {
    const el = ev.target.closest('[data-bb-action]');
    if (!el) return;
    switch (el.dataset.bbAction) {
        case 'toggle-secret':     toggleSecret(); break;
        case 'generate-password': generatePassword(); break;
        case 'generate-link':     generateLink(); break;
        case 'copy-link':         copyLink(); break;
        case 'preview':           setPreview(el.dataset.bbMode, el); break;
    }
});

// Przycisk oznaczania poufnego NIE moze zabrac zaznaczenia z edytora -
// toggleSecret czyta window.getSelection(), wiec bez tego klik czyscilby to,
// na czym ma zadzialac. Blokada idzie na mousedown, bo focus przenosi sie
// przed clickiem.
document.addEventListener('mousedown', function(ev) {
    if (ev.target.closest('[data-bb-keep-selection]')) ev.preventDefault();
});

// Formularz nie wysyla sie natywnie: link powstaje w przegladarce, a submit
// (np. Enter w polu liczbowym) przeladowalby strone i zgubil tresc edytora.
document.getElementById('createForm').addEventListener('submit', function(ev) {
    ev.preventDefault();
});
