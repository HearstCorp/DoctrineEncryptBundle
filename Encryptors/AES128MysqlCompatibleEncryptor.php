<?php

namespace VMelnik\DoctrineEncryptBundle\Encryptors;

/**
 * Class for AES256 encryption
 *
 * @author AlexanderC <self@alexanderc.me>
 */
class AES128MysqlCompatibleEncryptor implements EncryptorInterface
{

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
    public function __construct($key)
    {
        $this->secretKey = $this->mysqlAesKey($key);

        $this->initializationVector = mcrypt_create_iv(
            mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB),
            MCRYPT_DEV_URANDOM
        );
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($data)
    {
        // skip if not string
        if(!is_string($data) && !is_array($data)) {
            return $data;
        }

        if(is_array($data)) {
            $encodedArray = [];

            foreach($data as $key => $item) {
                $encodedArray[$key] = $this->encrypt($item);
            }

            return $encodedArray;
        }

        return $this->isAlreadyEncrypted($data) ? $data : $this->doEncrypt($data);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt($data)
    {
        // skip if not string
        if(!is_string($data) && !is_array($data)) {
            return $data;
        }

        if(is_array($data)) {
            $decodedArray = [];

            foreach($data as $key => $item) {
                $decodedArray[$key] = $this->decrypt($item);
            }

            return $decodedArray;
        }

        return $this->doDecrypt($data);
    }

    /**
     * @param string $data
     * @return bool
     */
    public function isAlreadyEncrypted($data)
    {
        $decodedData = base64_decode($data, true);

        // do not decode if broken or not base64
        if(false === $decodedData) {
            return false;
        }

        $decryptedData = mcrypt_decrypt(
            MCRYPT_RIJNDAEL_128,
            $this->secretKey,
            $decodedData,
            MCRYPT_MODE_ECB,
            $this->initializationVector
        );

        return false !== $decryptedData && $data !== $decryptedData;
    }

    /**
     * @param string $data
     * @return string
     */
    protected function doEncrypt($data)
    {
        return base64_encode(
            mcrypt_encrypt(
                MCRYPT_RIJNDAEL_128,
                $this->secretKey,
                $this->mysqlAesValue($data),
                MCRYPT_MODE_ECB,
                $this->initializationVector
            )
        );
    }

    /**
     * @param string $data
     * @return string
     */
    protected function doDecrypt($data)
    {
        $decodedData = base64_decode($data, true);

        // do not decode if broken or not base64
        if(false === $decodedData) {
            return $data;
        }

        $decryptedData = mcrypt_decrypt(
                MCRYPT_RIJNDAEL_128,
                $this->secretKey,
                $decodedData,
                MCRYPT_MODE_ECB,
                $this->initializationVector
            );

        return $this->mysqlAesPrepareDecryptedValue($decryptedData);
    }

    /**
     * @param string $value
     * @return string
     */
    protected function mysqlAesPrepareDecryptedValue($value)
    {
        $value = preg_replace(
            '/[\x00-\x08\x0B\x0C\x0E-\x1F\x80-\x9F]/u',
            '',
            $value
        );

        return $value;
    }

    /**
     * @param string $value
     * @return string
     */
    protected function mysqlAesValue($value)
    {
        $padValue = 16 - (strlen($value) % 16);

        return str_pad($value, (16 * (floor(strlen($value) / 16) + 1)), chr($padValue));
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
