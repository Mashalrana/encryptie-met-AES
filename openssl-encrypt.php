<?php

function encryptMessage($message, $key) {
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($algo = 'aes-128-gcm'));
    $encrypted = openssl_encrypt($message, $algo, $key, 0, $iv, $tag); 
    return ['iv' => base64_encode($iv), 'ciphertext' => base64_encode($encrypted), 'tag' => base64_encode($tag)];
}

function decryptMessage($iv, $ciphertext, $tag, $key) {
    $decrypted = openssl_decrypt(base64_decode($ciphertext), $algo = 'aes-128-gcm', $key, 0, base64_decode($iv), base64_decode($tag));
    return $decrypted;
}

list(, $message, $key) = $argv;

if (empty($message) || empty($key)) {
    die("Gebruik: php openssl-encrypt.php \"bericht\" \"sleutel\"\n");
}

$encryptedData = encryptMessage($message, $key);
echo "> ciphertext: " . $encryptedData['ciphertext'] . "\n";
echo "> origineletext: " . decryptMessage($encryptedData['iv'], $encryptedData['ciphertext'], $encryptedData['tag'], $key) . "\n";

?>
