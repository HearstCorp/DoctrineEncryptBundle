<?php

namespace VMelnik\DoctrineEncryptBundle\Encryptors;

/**
 * Class for AES256 encryption
 * 
 * @author Victor Melnik <melnikvictorl@gmail.com>
 * @author AlexanderC <self@alexanderc.me>
 */
class AES128MysqlCompatibleEncryptor implements EncryptorInterface {

    /**
     * @var string
     */
    private $secretKey;

    /**
     * @var string
     */
    private $initializationVector;

    /**
     * {@inheritdoc}
     */
    public function __construct($key) {
        $this->secretKey = $this->mysqlAesKey($key);

        $this->initializationVector = mcrypt_create_iv(
            mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB),
            MCRYPT_DEV_URANDOM
        );
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($data) {
        // skip if not string
        if(!is_string($data)) {
            return $data;
        }

        $pv = 16 - (strlen($data) % 16);
        $data = str_pad($data, (16 * (floor(strlen($data) / 16) + 1)), chr($pv));

        return base64_encode(mcrypt_encrypt(
            MCRYPT_RIJNDAEL_128,
            $this->secretKey,
            $data,
            MCRYPT_MODE_ECB,
            $this->initializationVector
        ));
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt($data) {
        $decodedData = base64_decode($data, true);

        // do not decode if nothing to decode
        if(false === $decodedData || base64_encode($decodedData) !== $data) {
            return $data;
        }

        return rtrim(mcrypt_decrypt(
            MCRYPT_RIJNDAEL_128,
            $this->secretKey,
            $decodedData,
            MCRYPT_MODE_ECB,
            $this->initializationVector
        ), "\0..\16");
    }

    /**
     * @param string $key
     * @return string
     */
    protected function mysqlAesKey($key)
    {
        $newKey = str_repeat(chr(0), 16);

        for($i = 0, $len = strlen($key); $i < $len; $i++) {
            $newKey[$i % 16] = $newKey[$i % 16] ^ $key[$i];
        }

        return $newKey;
    }
}
