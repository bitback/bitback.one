<?php
define('APP_NAME', 'bitback.one');
define('DATA_DIR', __DIR__ . '/../data');
define('TRASH_DIR', __DIR__ . '/../trash');
define('RATE_LIMIT_DIR', __DIR__ . '/../data/_ratelimit');
define('RATE_LIMIT_MAX', 10);        // max linków na IP / godzinę
define('RATE_LIMIT_WINDOW', 3600);   // okno w sekundach
define('DEFAULT_EXPIRE_DAYS', 30);
define('DEFAULT_MAX_VIEWS', 15);
define('DEFAULT_DELETE_DAYS', 360);
// bulk (korespondencja seryjna) - osobny bucket i limity paczki
define('RATE_LIMIT_BATCH_MAX', 10);          // max paczek na IP / okno
define('RATE_LIMIT_BATCH_WINDOW', 3600);     // okno batcha w sekundach
define('BATCH_MAX_RECORDS', 200);            // max osób w jednej paczce
define('BATCH_MAX_TOTAL_BYTES', 8 * 1024 * 1024); // suma blobów paczki (8 MB)
define('CIPHER_METHOD', 'aes-256-cbc');
define('IP_HASH_SALT', 'zmien-na-losowy-ciag-min-24-znakow');
