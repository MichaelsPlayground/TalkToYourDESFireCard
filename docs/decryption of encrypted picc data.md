// this is a PHP script to decrypt the encrypted pics data
// it does NOT decrypted encrypted file data and does NOT verify the appended CMAC
// as PHP's OpenSSL implementation does not provide an AES-128 CMAC functionality
// live implementation: https://replit.com/@javacrypto/PhpDecryptSunMessage#main.php
// Java Code: TalkToYourDESFireCard/app/src/main/java/de/androidcrypto/talktoyourdesfirecard/AesCmac.java 

<?php

function calculateSha256($input) {
    return hash('sha256', $input, true);
}

function bytesToHex($input) {
    return bin2hex($input);
}

function hexStringToByteArray($input) {
    return hex2bin($input);
}

function base64Encoding($input)
{ return base64_encode($input); }

function base64Decoding($input)
{ return base64_decode($input); }

function aesCbcDecryptFromBase64($key, $data)
{
    list($iv, $encryptedData) = explode(':', $data, 2);
    return openssl_decrypt(base64_decode($encryptedData), 'aes-256-cbc', $key, OPENSSL_RAW_DATA, base64_decode($iv));
}

function aesCbcDecryptFromHex($key, $iv, $data)
{  
  $keyBytes = hexStringToByteArray($key);
  $ivBytes = hexStringToByteArray($iv);
  $dataBytes = hexStringToByteArray($data);
  $plainData = openssl_decrypt($dataBytes, 'aes-128-cbc', $keyBytes, OPENSSL_NO_PADDING, $ivBytes);
  //$plainData = openssl_decrypt($dataBytes, 'aes-128-cbc', $keyBytes, OPENSSL_RAW_DATA, $ivBytes);
  $msg = openssl_error_string();
  echo '### msg: ' . $msg . PHP_EOL;
  return $plainData;
}

function aesCbcEncryptFromHex($key, $iv, $data)
{  
  $keyBytes = hexStringToByteArray($key);
  $ivBytes = hexStringToByteArray($iv);
  $dataBytes = hexStringToByteArray($data);
  $plainData = openssl_encrypt($dataBytes, 'aes-128-cbc', $keyBytes, OPENSSL_NO_PADDING, $ivBytes);
  //$plainData = openssl_decrypt($dataBytes, 'aes-128-cbc', $keyBytes, OPENSSL_RAW_DATA, $ivBytes);
  $msg = openssl_error_string();
  echo '### msg: ' . $msg . PHP_EOL;
  return $plainData;
}

/**
 * Convert $endian hex string to specified $format
 * 
 * @param string $endian Endian HEX string
 * @param string $format Endian format: 'N' - big endian, 'V' - little endian
 * 
 * @return string 
 */
function formatEndian($endian, $format = 'N') {
    $endian = intval($endian, 16);      // convert string to hex
    $endian = pack('L', $endian);       // pack hex to binary sting (unsinged long, machine byte order)
    $endian = unpack($format, $endian); // convert binary sting to specified endian format

    //return sprintf("%'.06x", $endian[1]); // return endian as a hex string (with padding zero)
    return sprintf("%'.08x", $endian[1]); // return endian as a hex string (with padding zero)
}
/*
$endian = '18000000';
$big    = formatEndian($endian, 'N'); // string "00000018"
$little = formatEndian($endian, 'V'); // string "18000000"
*/

// build the cmac Input
// the readCounter is in LSB encoding ("inversed")
function getCmacInput($uidHex, $readCounterHex) {
  $output = "C33C00010080"; // header
  $output = $output . $uidHex . $readCounterHex;
  return $output;
}





echo 'Decrypt a SUN message' . PHP_EOL;

$encPiccData = "7611174D92F390458FF7E15ACFD2579F";
$encFileData = "F9FB7442DB2E0BE631CD4E3BCF74276E";
$cmac = "69784EF122D0CB5F";

/*
expected values:
Cryptographic signature validated.
Encryption mode: AES
PICC Data Tag: c7
NFC TAG UID: 04514032501490
Read counter: 82
File data (hex): 30313032303330343035303630373038
File data (UTF-8): 0102030405060708
*/  

$sdmMetaReadKey = "00000000000000000000000000000000"; // AES-128 key
$sdmReadKey = "00000000000000000000000000000000"; // AES-128 key
$initVector = "00000000000000000000000000000000";

echo '=== Decrypt EncryptedPiccData ===' . PHP_EOL;

echo 'encPiccData:    ' . $encPiccData . PHP_EOL;
echo 'sdmMetaReadKey: ' . $sdmMetaReadKey . PHP_EOL;
echo 'initVector:     ' . $initVector . PHP_EOL;

$plainPiccData = aesCbcDecryptFromHex($sdmMetaReadKey, $initVector, $encPiccData);

$plainPiccDataHex = bytesToHex($plainPiccData);
echo 'plainPiccData:  ' . $plainPiccDataHex . PHP_EOL;

// split data depending of first byte, here done on hex encoded basis
$piccDataTag = substr($plainPiccDataHex, 0, 1);
$isUidMirrored = false;
$isReadCounterMirrored = false;
if ($piccDataTag == "c") {
  // UID & Read Counter is mirrored
  echo 'UID & Read Counter is mirrored' . PHP_EOL;
  $isUidMirrored = true;
  $isReadCounterMirrored = true;
}
if ($piccDataTag == "8") {
  // UID is mirrored
  echo 'UID is mirrored' . PHP_EOL;
  $isUidMirrored = true;
}
if ($piccDataTag == "4") {
  // Read Counter is mirrored
  echo 'Read Counter is mirrored' . PHP_EOL;
  $isReadCounterMirrored = true;
}

$uidLength = substr($plainPiccDataHex, 1, 1);
// $uidLength is 0 when not mirrored

$uid = "";
$readCounter = "";
$offset = 2;
if ($isUidMirrored == true) {
  // length is 2 * uidLength as in hex encoding
  $uid = substr($plainPiccDataHex, $offset, (2 * $uidLength));
  $offset = $offset + (2 * $uidLength);
}
if ($isReadCounterMirrored == true) {
  // length is 6 as in hex encoding
  $readCounter = substr($plainPiccDataHex, $offset, 6);
  $offset = $offset + 6;
}
// the readCounter is in LSB encoding means the Lowest value is at the beginning
// eg: '520000' is '000052' = 82 decimal
// don't forget to add the trailing '00'
$readCounterValue = hexdec(formatEndian($readCounter . "00", 'N'));

// decrypt Encrypted File Data
echo PHP_EOL;
echo '=== Decrypt EncryptedFileData ===' . PHP_EOL;
echo 'encFileData:    ' . $encFileData . PHP_EOL;
echo 'sdmReadKey:     ' . $sdmReadKey . PHP_EOL;
echo 'initVector:     ' . $sdmMetaReadKey . PHP_EOL;

$cmacInput = getCmacInput($uid, $readCounter);
echo '$cmacInput:     ' . $cmacInput . PHP_EOL;

echo PHP_EOL;
echo '** NOTE: as PHP with OpenSSL does not have a build in AES128-CMAC function this is NOT SUPPORTED by this class, sorry. **'. PHP_EOL;
echo PHP_EOL;

// verify appended CMAC
echo PHP_EOL;
echo '=== VERIFY APPENDED CMAC ===' . PHP_EOL;

echo PHP_EOL;
echo '** NOTE: as PHP with OpenSSL does not have a build in AES128-CMAC function this is NOT SUPPORTED by this class, sorry. **'. PHP_EOL;
echo PHP_EOL;


echo PHP_EOL;
echo '=== plainPiccData ===' . PHP_EOL;
echo 'piccDataTag: ' . $piccDataTag . PHP_EOL;
echo 'uidLength:   ' . $uidLength . PHP_EOL;
echo 'uid:         ' . $uid . PHP_EOL;
echo 'readCounter: ' . $readCounter . PHP_EOL;
echo 'readCounter: ' . $readCounterValue . PHP_EOL;
echo '' . PHP_EOL;
echo '' . PHP_EOL;
echo '' . PHP_EOL;


$ciphers             = openssl_get_cipher_methods();
$ciphers_and_aliases = openssl_get_cipher_methods(true);
$cipher_aliases      = array_diff($ciphers_and_aliases, $ciphers);
echo 'openssl cipher methods' . $cipher_aliases . PHP_EOL;
print_r($cipher_aliases);

/*
// enc test
$plain = "AA0000000000000000000000000000BB";
echo 'plainHex: ' . $plainHex . PHP_EOL;
$ciph = aesCbcEncryptFromHex($sdmMetaReadKey, $initVector, $plain);
$ciphHex = bytesToHex($ciph);
echo 'ciphHex:  ' . $ciphHex . PHP_EOL;

// dec test
$dec = aesCbcDecryptFromHex($sdmMetaReadKey, $initVector, $ciphHex);
$decHex = bytesToHex($dec);
echo 'decHex:  ' . $dechHex . PHP_EOL;
*/

/*

$plaintext = "The quick brown fox jumps over the lazy dog";
echo 'plaintext:                ' . $plaintext . PHP_EOL;

$sha256Value = calculateSha256($plaintext);
echo 'sha256Value (hex) length: ' . strlen($sha256Value) . " data: " . bytesToHex($sha256Value) . PHP_EOL;

$sha256Base64 = base64Encoding($sha256Value);
echo 'sha256Value (base64):     ' . $sha256Base64 . PHP_EOL;

$sha256ValueDecoded = base64Decoding($sha256Base64);
echo 'sha256Base64 decoded to a byte array:' . PHP_EOL;
echo 'sha256Value (hex) length: ' . strlen($sha256ValueDecoded) . " data: " . bytesToHex($sha256ValueDecoded) . PHP_EOL;

$sha256HexString = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
$sha256Hex = hexStringToByteArray($sha256HexString);
echo 'sha256HexString converted to a byte array:' . PHP_EOL;
echo 'sha256Value (hex) length: ' . strlen($sha256Hex) . " data: " . bytesToHex($sha256Hex) . PHP_EOL;
*/
?>