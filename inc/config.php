<?php
define('DATA_DIR', __DIR__ . '/../data');
define('TRASH_DIR', __DIR__ . '/../trash');
define('RATE_LIMIT_DIR', __DIR__ . '/../data/_ratelimit');
define('RATE_LIMIT_MAX', 10);        // max linków na IP / godzinę
define('RATE_LIMIT_WINDOW', 3600);   // okno w sekundach
define('DEFAULT_EXPIRE_DAYS', 14);
define('DEFAULT_MAX_VIEWS', 5);
define('DEFAULT_DELETE_DAYS', 90);
define('CIPHER_METHOD', 'aes-256-cbc');
