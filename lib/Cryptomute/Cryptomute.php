<?php

namespace Cryptomute;

use InvalidArgumentException;
use LogicException;

/**
 * Cryptomute
 *
 * (c) 2016 Piotr Gołębiewski
 *
 * Released under MIT license.
 * https://github.com/loostro/cryptomute
 *
 * Format preserving data encryption and decryption based on feistel network.
 */
class Cryptomute
{
    const VERSION = '1.0.2';

    const PASSWORD_MIN_LENGTH = 16;

    const KEY_MIN_LENGTH = 16;

    const MIN_ROUNDS = 3;

    const MIN_POOL_SIZE = '999';

    /**
     * @var array
     */
    protected $allowedCiphers = [
        'aes-128-cbc' => ['iv' => true, 'length' => 128],
    ];

    /**
     * @var array
     */
    protected $allowedDataTypes = [
        'bin' => '/^[0-1]+$/',
        'dec' => '/^[0-9]+$/',
        'hex' => '/^[a-f0-9]+$/',
    ];

    /**
     * @var string
     */
    protected $maxValue;

    /**
     * @var string
     */
    protected $cipher;

    /**
     * @var string
     */
    protected $password;

    /**
     * @var string
     */
    protected $key;

    /**
     * @var array
     */
    protected $roundKeys;

    /**
     * @var string
     */
    protected $iv;

    /**
     * @var int
     */
    protected $rounds;

    /**
     * @var int
     */
    protected $cipherLength;

    /**
     * @var int
     */
    protected $blockSize;

    /**
     * @var int
     */
    protected $bitSize;

    /**
     * @var int
     */
    protected $decSize;

    /**
     * @var int
     */
    protected $hexSize;

    /**
     * @var int
     */
    protected $sideSize;

    /**
     * Cryptomute constructor.
     *
     * @param string $minValue Minimum value. String representation of positive integer value or zero.
     * @param string $maxValue Maximum value. String representation of positive integer value.
     * @param string $cipher   Cipher used to encrypt.
     * @param string $password Encryption password.
     * @param string $key      Initial key, from which all round keys are derrived.
     * @param int    $rounds   Number of rounds.
     * @param string $iv       Initialization vector, required only if applies to given cipher.
     *
     * @throws InvalidArgumentException If provided invalid constructor parameters.
     * @throws LogicException           If side size is longer than cipher length.
     */
    public function __construct($minValue, $maxValue, $cipher, $password, $key, $rounds = 3, $iv = '')
    {
        if (preg_match('/^([1-9][0-9]*)|([0]{1})$/', $minValue) !== 1) {
            throw new InvalidArgumentException(
                'Min value must contain only digits.'
            );
        }

        if (preg_match('/^[1-9][0-9]*$/', $maxValue) !== 1) {
            throw new InvalidArgumentException(
                'Max value must start with a nonzero digit and contain only digits.'
            );
        }

        if (gmp_cmp($maxValue, $minValue) !== 1) {
            throw new InvalidArgumentException('Max value must be greater than min value.');
        }

        $this->minValue = $minValue;
        $this->maxValue = $maxValue;
        $this->binSize = 2;

        // find the minimum number of even bits to span whole set
        $span = gmp_init('4', 10);
        $multiplier = gmp_init('4', 10);
        do {
            $this->binSize += 2;
            $span = gmp_mul ($span, $multiplier);
        } while (gmp_cmp($span, $this->maxValue) !== 1);

        $this->decSize = strlen($this->maxValue);
        $this->hexSize = $this->binSize / 4;

        $this->sideSize = (int) $this->binSize / 2;

        if (!array_key_exists($cipher, $this->allowedCiphers)) {
            throw new InvalidArgumentException(sprintf(
                'Cipher must be one of "%s".',
                implode(', ', array_keys($this->allowedCiphers))
            ));
        }

        $this->cipher = $cipher;
        $this->cipherLength = $this->allowedCiphers[$cipher]['length'];

        if ($this->sideSize > $this->cipherLength) {
            throw new LogicException(sprintf(
                'Side size (%d bits) must be less or equal to cipher length (%d bits)',
                $this->sideSize,
                $this->cipherLength
            ));
        }


        if (!is_int($rounds) || $rounds < self::MIN_ROUNDS) {
            throw new InvalidArgumentException(sprintf(
                'Number of rounds must be an integer greater or equal %d',
                self::MIN_ROUNDS
            ));
        }

        $this->rounds = $rounds;

        if ($this->allowedCiphers[$cipher]['iv']) {
            $this->blockSize = openssl_cipher_iv_length($this->cipher);

            if (strlen($iv) !== $this->blockSize) {
                throw new InvalidArgumentException(sprintf(
                    'Initialization vector of %d bytes is required for cipher "%s".',
                    $this->blockSize,
                    $this->cipher
                ));
            }

            $this->iv = $iv;
        }

        $this->setPassword($password, false);
        $this->setKey($key, false);
        $this->generateRoundKeys();
    }

    /**
     * Set password.
     *
     * @param string $password
     * @param bool   $regenerateRoundKeys
     *
     * @throws InvalidArgumentException If provided invalid password.
     */
    public function setPassword($password, $regenerateRoundKeys = true)
    {
        if (strlen($password) < self::PASSWORD_MIN_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'Password must be at least %d characters long.',
                self::PASSWORD_MIN_LENGTH
            ));
        }

        $this->password = $password;

        if ($regenerateRoundKeys) {
            $this->generateRoundKeys();
        }
    }

    /**
     * Set key.
     *
     * @param string $key
     * @param bool   $regenerateRoundKeys
     *
     * @throws InvalidArgumentException If provided invalid password.
     */
    public function setKey($key, $regenerateRoundKeys = true)
    {
        if (strlen($key) < self::KEY_MIN_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'Key must be at least %d characters long.',
                self::KEY_MIN_LENGTH
            ));
        }

        $this->key = $key;

        if ($regenerateRoundKeys) {
            $this->generateRoundKeys();
        }
    }

    /**
     * Generates round keys.
     */
    public function generateRoundKeys()
    {
        $this->roundKeys = [];
        $prevKey = $this->_encrypt($this->key);
        for ($i = 1; $i <= $this->rounds; $i++) {
            $prevKey = $this->_encrypt($prevKey);
            $this->roundKeys[$i] = substr(DataConverter::rawToBin($prevKey), -1 * $this->sideSize);
        }
    }

    /**
     * Encrypts input data.
     *
     * @param string $input String representation of input number.
     * @param string $type  Input number type.
     * @param bool   $pad
     *
     * @throws InvalidArgumentException If provided invalid type.
     * @throws InvalidArgumentException If provided data does not match type pattern.
     *
     * @return string Outputs encrypted data in the same format as input data.
     */
    public function encrypt($input, $type = 'dec', $pad = false)
    {
        if (!array_key_exists($type, $this->allowedDataTypes)) {
            throw new InvalidArgumentException(sprintf(
                'Type must be one of "%s", but given "%s".',
                implode(', ', array_keys($this->allowedDataTypes)),
                $type
            ));
        }

        if (preg_match($this->allowedDataTypes[$type], $input) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'Input data does not match pattern "%s".',
                $this->allowedDataTypes[$type]
            ));
        }

        switch ($type) {
            case 'bin':
                $binary = DataConverter::pad($input, $this->binSize);
                break;
            case 'dec':
                $binary = DataConverter::decToBin($input, $this->binSize);
                break;
            case 'hex':
                $binary = DataConverter::hexToBin($input, $this->binSize);
                break;
        }

        for ($i = 1; $i <= $this->rounds; $i++) {
            $left = substr($binary, 0, $this->sideSize);
            $right = substr($binary, -1 * $this->sideSize);

            $key = $this->roundKeys[$i];
            $round = $this->_round($right, $key);

            $newLeft = $right;
            $newRight = $this->_binaryXor($left, $round);

            $binary = $newLeft . $newRight;
        }

        switch ($type) {
            case 'bin':
                $output = DataConverter::pad($binary, ($pad ? $this->binSize : 0));
                break;
            case 'dec':
                $output = DataConverter::binToDec($binary, ($pad ? $this->decSize : 0));
                break;
            case 'hex':
                $output = DataConverter::binToHex($binary, ($pad ? $this->hexSize : 0));
                break;
        }

        $compare = DataConverter::binToDec($binary);

        return (gmp_cmp($this->minValue, $compare) === 1 || gmp_cmp($compare, $this->maxValue) === 1)
            ? $this->encrypt($output, $type, $pad)
            : $output;
    }

    /**
     * Decrypts input data.
     *
     * @param string $input
     * @param string $type
     * @param bool   $pad
     *
     * @throws InvalidArgumentException If provided invalid type.
     * @throws InvalidArgumentException If provided data does not match type pattern.
     *
     * @return string Outputs encrypted data in the same format as input data.
     */
    public function decrypt($input, $type = 'dec', $pad = false)
    {
        if (!array_key_exists($type, $this->allowedDataTypes)) {
            throw new InvalidArgumentException(sprintf(
                'Type must be one of "%s".',
                implode(', ', array_keys($this->allowedDataTypes))
            ));
        }

        if (preg_match($this->allowedDataTypes[$type], $input) !== 1) {
            echo "\n\n ARGH: $input \n\n";
            throw new InvalidArgumentException(sprintf(
                'Input data does not match pattern "%s".',
                $this->allowedDataTypes[$type]
            ));
        }

        switch ($type) {
            case 'bin':
                $binary = DataConverter::pad($input, $this->binSize);
                break;
            case 'dec':
                $binary = DataConverter::decToBin($input, $this->binSize);
                break;
            case 'hex':
                $binary = DataConverter::hexToBin($input, $this->binSize);
                break;
        }

        for ($i = $this->rounds; $i > 0; $i--) {
            $left = substr($binary, 0, $this->sideSize);
            $right = substr($binary, -1 * $this->sideSize);

            $key = $this->roundKeys[$i];
            $round = $this->_round($left, $key);

            $newLeft = $this->_binaryXor($right, $round);
            $newRight = $left;

            $binary = $newLeft . $newRight;
        }

        switch ($type) {
            case 'bin':
                $output = DataConverter::pad($binary, ($pad ? $this->binSize : 0));
                break;
            case 'dec':
                $output = DataConverter::binToDec($binary, ($pad ? $this->decSize : 0));
                break;
            case 'hex':
                $output = DataConverter::binToHex($binary, ($pad ? $this->hexSize : 0));
                break;
        }

        $compare = DataConverter::binToDec($binary);

        return (gmp_cmp($this->minValue, $compare) === 1 || gmp_cmp($compare, $this->maxValue) === 1)
            ? $this->decrypt($output, $type, $pad)
            : $output;
    }

    /**
     * Encrypt helper.
     *
     * @param string $input
     *
     * @return string Steam of encrypted bytes.
     */
    private function _encrypt($input)
    {
        return ($this->allowedCiphers[$this->cipher]['iv'])
            ? openssl_encrypt($input, $this->cipher, $this->password, true, $this->iv)
            : openssl_encrypt($input, $this->cipher, $this->password, true);
    }

    /**
     * Round function helper.
     *
     * @param string $input
     * @param string $key
     *
     * @return string Binary string.
     */
    private function _round($input, $key)
    {
        $bin = DataConverter::rawToBin($this->_encrypt($input . $key));

        return substr($bin, -1 * $this->sideSize);
    }

    /**
     * Binary xor helper.
     *
     * @param string $left
     * @param string $round
     *
     * @return string Binary string.
     */
    private function _binaryXor($left, $round)
    {
        $xOr = gmp_xor(
            gmp_init($left, 2),
            gmp_init($round, 2)
        );

        $bin = gmp_strval($xOr, 2);

        return str_pad($bin, $this->sideSize, '0', STR_PAD_LEFT);
    }
}