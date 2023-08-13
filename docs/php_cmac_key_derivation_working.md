# PHP code for generating an AES-128 CMAC

This code is necessary to derive sub key (like SesAuthEntKey or SesAuthMacKey) and is working !

It is taken from the crypto library **PHP-CryptLib** written by **Anthony Ferrara** ("ircmaxell").

The full code is available here: https://github.com/ircmaxell/PHP-CryptLib/tree/master.

// see live example: https://replit.com/@javacrypto/PhpAes128CmacDetailed2#main.php

```plaintext
result:
Calculate an AES-128 CMAC

called setKey with $key: +~(�Ҧ��    �O<
### msg: 
### msg: 
$cmac:    070a16b46b4d4144f79bdd9dd04a287c
$cmacExp: 070a16b46b4d4144f79bdd9dd04a287c
called setKey with $key: 
### msg: 
### msg: 
$cmac:    3fb5f6e3a807a03d5e3570ace393776f
$cmacExp: 3FB5F6E3A807A03D5E3570ACE393776F
```

This is the code:

```php
<?php

$cmacKey;

function setKey($key) {
  global $cmacKey;
  $cmacKey = $key;
  //echo 'called setKey with $key: ' . bin2hex($key) . PHP_EOL;
  echo 'called setKey with $key: ' . $key . PHP_EOL;
}

function encryptBlock($data) {
  global $cmacKey;
  $iv = pack("H*", '00000000000000000000000000000000');
  $cipherData = openssl_encrypt($data, 'aes-128-cbc', $cmacKey, OPENSSL_NO_PADDING, $iv);
  //$plainData = openssl_decrypt($dataBytes, 'aes-128-cbc', $keyBytes, OPENSSL_RAW_DATA, $ivBytes);
  $msg = openssl_error_string();
  echo '### msg: ' . $msg . PHP_EOL;
  return $cipherData;
}

function bytesToHex($input) {
    return bin2hex($input);
}

function hexStringToByteArray($input) {
    return hex2bin($input);
}

//=============================================
// source: https://github.com/ircmaxell/PHP-CryptLib/blob/master/lib/CryptLib/MAC/Implementation/CMAC.php

    /**
     * Generate the MAC using the supplied data
     *
     * @param string $data The data to use to generate the MAC with
     * @param string $key  The key to generate the MAC
     * @param int    $size The size of the output to return
     *
     * @return string The generated MAC of the appropriate size
     */
    function generate($data, $key, $size = 0) {
        $blockSize = 16;
        if ($size == 0) {
            $size = $blockSize;
        }
        if ($size > $blockSize) {
            throw new \OutOfRangeException(
                sprintf(
                    'The size is too big for the cipher primitive [%d:%d]',
                    $size,
                    $blockSize
                )
            );
        }
        //$this->cipher->setKey($key);
        setKey($key);
        $keys    = generateKeys();
        $mBlocks = splitDataIntoMBlocks($data, $keys);
        $cBlock  = str_repeat(chr(0), $blockSize);
        foreach ($mBlocks as $key => $block) {
            //$cBlock = $this->cipher->encryptBlock($cBlock ^ $block);
          $cBlock = encryptBlock($cBlock ^ $block);
        }
        return substr($cBlock, 0, $size);
    }


    /**
     * Generate a pair of keys by encrypting a block of all 0's, and then
     * maniuplating the result
     *
     * @return array The generated keys
     */
    function generateKeys() {
        $keys      = array();
        $blockSize = 16;
        $rVal      = getRValue($blockSize);
        $text      = str_repeat(chr(0), $blockSize);
        //$lVal      = $this->cipher->encryptBlock($text);
        $lVal      = encryptBlock($text);
        $keys[0]   = leftShift($lVal, 1);
        if (ord(substr($lVal, 0, 1)) > 127) {
            $keys[0] = $keys[0] ^ $rVal;
        }
        $keys[1] = leftShift($keys[0], 1);
        if (ord(substr($keys[0], 0, 1)) > 127) {
            $keys[1] = $keys[1] ^ $rVal;
        }
        return $keys;
    }

    /**
     * Get an RValue based upon the block size
     *
     * @param int $size The size of the block in bytes
     *
     * @see http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
     * @return string A RValue of the appropriate block size
     */
    function getRValue($size) {
        switch ($size * 8) {
            case 64:
                return str_repeat(chr(0), 7) . chr(0x1B);
            case 128:
                return str_repeat(chr(0), 15) . chr(0x87);
            default:
        }
        throw new \RuntimeException('Unsupported Block Size For The Cipher');
    }

    function leftShift($data, $bits) {
        $mask   = (0xff << (8 - $bits)) & 0xff;
        $state  = 0;
        $result = '';
        $length = strlen($data);
        for ($i = $length - 1; $i >= 0; $i--) {
            $tmp     = ord($data[$i]);
            $result .= chr(($tmp << $bits) | $state);
            $state   = ($tmp & $mask) >> (8 - $bits);
        }
        return strrev($result);
    }

    /**
     * Split the data into appropriate block chunks, encoding with the kyes
     *
     * @param string $data The data to split
     * @param array  $keys The keys to use for encoding
     *
     * @return array The array of chunked and encoded data
     */
    function splitDataIntoMBlocks($data, array $keys) {
        $blockSize = 16;
        $data      = str_split($data, $blockSize);
        $last      = end($data);
        if (strlen($last) != $blockSize) {
            //Pad the last element
            $last .= chr(0x80) . str_repeat(chr(0), $blockSize - 1 - strlen($last));
            $last  = $last ^ $keys[1];
        } else {
            $last = $last ^ $keys[0];
        }
        $data[count($data) - 1] = $last;
        return $data;
    }

//=============================================

echo 'Calculate an AES-128 CMAC' . PHP_EOL;
echo PHP_EOL;

$key = '2b7e151628aed2a6abf7158809cf4f3c'; // from test/Data/Vectors/cmac-aes ...
$msg = '6bc1bee22e409f96e93d7e117393172a'; // from test/Data/Vectors/cmac-aes ...

$key = pack("H*", '2b7e151628aed2a6abf7158809cf4f3c');
$msg = pack("H*", '6bc1bee22e409f96e93d7e117393172a');

$cmac = generate($msg,$key); 
echo '$cmac:    ' . bytesToHex($cmac) . PHP_EOL;
echo '$cmacExp: ' . '070a16b46b4d4144f79bdd9dd04a287c' . PHP_EOL;
// $cmac should be 070a16b46b4d4144f79bdd9dd04a287c

// data from vectors from NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf page 15
$key2 = pack("H*", '00000000000000000000000000000000');
$msg2 = pack("H*", '3CC30001008004DE5F1EACC0403D0000');

$cmac = generate($msg2,$key2); 
echo '$cmac:    ' . bytesToHex($cmac) . PHP_EOL;
echo '$cmacExp: ' . '3FB5F6E3A807A03D5E3570ACE393776F' . PHP_EOL;
// this is working !!

?>

```

