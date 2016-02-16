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
    const VERSION = '1.0.0';

    const KEY_MIN_LENGTH = 16;

    const MIN_ROUNDS = 3;

    const DEFAULT_MIN_VALUE = '0';

    const DEFAULT_MAX_VALUE = '9999999999';

    /**
     * @var array
     */
    public static $allowedCiphers = [
        'aes-128-cbc' => ['iv' => true, 'length' => 128],
    ];

    /**
     * @var array
     */
    public static $allowedBases = [
        2  => '/^[0-1]+$/',
        10 => '/^[0-9]+$/',
        16 => '/^[a-f0-9]+$/',
    ];

    /**
     * @var string
     */
    protected $minValue;

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
    protected $binSize;

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
     * @param string $cipher  Cipher used to encrypt.
     * @param string $baseKey Base key, from which all round keys are derrived.
     * @param int    $rounds  Number of rounds.
     *
     * @throws InvalidArgumentException If provided invalid constructor parameters.
     * @throws LogicException           If side size is longer than cipher length.
     */
    public function __construct($cipher, $baseKey, $rounds = 3)
    {
        if (!array_key_exists($cipher, self::$allowedCiphers)) {
            throw new InvalidArgumentException(sprintf(
                'Cipher must be one of "%s".',
                implode(', ', array_keys(self::$allowedCiphers))
            ));
        }

        $this->cipher = $cipher;
        $this->cipherLength = self::$allowedCiphers[$cipher]['length'];
        $this->setValueRange(self::DEFAULT_MIN_VALUE, self::DEFAULT_MAX_VALUE);

        if (!is_int($rounds) || $rounds < self::MIN_ROUNDS) {
            throw new InvalidArgumentException(sprintf(
                'Number of rounds must be an integer greater or equal %d',
                self::MIN_ROUNDS
            ));
        }

        $this->rounds = $rounds;

        if (strlen($baseKey) < self::KEY_MIN_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'Key must be at least %d characters long.',
                self::KEY_MIN_LENGTH
            ));
        }

        $this->key = $baseKey;
    }

    /**
     * Set value range and pad sizes.
     *
     * @param string $minValue Minimum value. String representation of positive integer value or zero.
     * @param string $maxValue Maximum value. String representation of positive integer value.
     *
     * @throws InvalidArgumentException If provided invalid parameters.
     *
     * @return Cryptomute
     */
    public function setValueRange($minValue, $maxValue)
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

        // find the minimum number of even bits to span whole set
        $this->binSize = 2;
        $span = gmp_init('4', 10);
        $multiplier = gmp_init('4', 10);
        do {
            $this->binSize += 2;
            $span = gmp_mul ($span, $multiplier);
        } while (gmp_cmp($span, $this->maxValue) !== 1);

        $this->decSize = strlen($this->maxValue);
        $this->hexSize = $this->binSize / 4;

        $this->sideSize = (int) $this->binSize / 2;

        if ($this->sideSize > $this->cipherLength) {
            throw new LogicException(sprintf(
                'Side size (%d bits) must be less or equal to cipher length (%d bits)',
                $this->sideSize,
                $this->cipherLength
            ));
        }

        return $this;
    }

    /**
     * Encrypts input data.
     *
     * @param string      $input    String representation of input number.
     * @param int         $base     Input number base.
     * @param bool        $pad      Pad left with zeroes?
     * @param string|null $password Encryption password.
     * @param string|null $iv       Encryption initialization vector. Must be unique!
     *
     * @return string Outputs encrypted data in the same format as input data.
     */
    public function encrypt($input, $base = 10, $pad = false, $password = null, $iv = null)
    {
        $this->_validateInput($input, $base);
        $this->_validateIv($iv);
        $hashPassword = $this->_hashPassword($password);
        $roundKeys = $this->_roundKeys($hashPassword, $iv);

        $binary = $this->_convertToBin($input, $base);

        for ($i = 1; $i <= $this->rounds; $i++) {
            $left = substr($binary, 0, $this->sideSize);
            $right = substr($binary, -1 * $this->sideSize);

            $key = $roundKeys[$i];
            $round = $this->_round($right, $key, $hashPassword, $iv);

            $newLeft = $right;
            $newRight = $this->_binaryXor($left, $round);

            $binary = $newLeft . $newRight;
        }

        $output = $this->_convertFromBin($binary, $base, $pad);
        $compare = DataConverter::binToDec($binary);

        return (gmp_cmp($this->minValue, $compare) === 1 || gmp_cmp($compare, $this->maxValue) === 1)
            ? $this->encrypt($output, $base, $pad, $password, $iv)
            : $output;
    }

    /**
     * Decrypts input data.
     *
     * @param string      $input    Encrypted input.
     * @param int         $base     Input data base.
     * @param bool        $pad      Pad left with zeroes?
     * @param string|null $password Decryption password.
     * @param string|null $iv       Decryption initialization vector.
     *
     * @return string Outputs encrypted data in the same format as input data.
     */
    public function decrypt($input, $base = 10, $pad = false, $password = null, $iv = null)
    {
        $this->_validateInput($input, $base);
        $this->_validateIv($iv);
        $hashPassword = $this->_hashPassword($password);
        $roundKeys = $this->_roundKeys($hashPassword, $iv);

        $binary = $this->_convertToBin($input, $base);

        for ($i = $this->rounds; $i > 0; $i--) {
            $left = substr($binary, 0, $this->sideSize);
            $right = substr($binary, -1 * $this->sideSize);

            $key = $roundKeys[$i];
            $round = $this->_round($left, $key, $hashPassword, $iv);

            $newLeft = $this->_binaryXor($right, $round);
            $newRight = $left;

            $binary = $newLeft . $newRight;
        }

        $output = $this->_convertFromBin($binary, $base, $pad);
        $compare = DataConverter::binToDec($binary);

        return (gmp_cmp($this->minValue, $compare) === 1 || gmp_cmp($compare, $this->maxValue) === 1)
            ? $this->decrypt($output, $base, $pad, $password, $iv)
            : $output;
    }

    /**
     * Encrypt helper.
     *
     * @param string      $input
     * @param string      $password
     * @param string|null $iv
     *
     * @return string Steam of encrypted bytes.
     */
    private function _encrypt($input, $password, $iv = null)
    {
        return (self::$allowedCiphers[$this->cipher]['iv'])
            ? openssl_encrypt($input, $this->cipher, $password, true, $iv)
            : openssl_encrypt($input, $this->cipher, $password, true);
    }

    /**
     * Round function helper.
     *
     * @param string      $input
     * @param string      $key
     * @param string      $hashPassword
     * @param string|null $iv
     *
     * @return string Binary string.
     */
    private function _round($input, $key, $hashPassword, $iv = null)
    {
        $bin = DataConverter::rawToBin($this->_encrypt($input . $key, $hashPassword, $iv));

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

    /**
     * Helper method converting input data to binary string.
     *
     * @param string $input
     * @param string $base
     *
     * @return string
     */
    private function _convertToBin($input, $base)
    {
        switch ($base) {
            case 2:
                return DataConverter::pad($input, $this->binSize);
            case 10:
                return DataConverter::decToBin($input, $this->binSize);
            case 16:
                return DataConverter::hexToBin($input, $this->binSize);
        }
    }

    /**
     * Helper method converting input data from binary string.
     *
     * @param string $binary
     * @param string $type
     * @param string $pad
     *
     * @return string
     */
    private function _convertFromBin($binary, $base, $pad)
    {
        switch ($base) {
            case 2:
                return DataConverter::pad($binary, ($pad ? $this->binSize : 0));
            case 10:
                return DataConverter::binToDec($binary, ($pad ? $this->decSize : 0));
            case 16:
                return DataConverter::binToHex($binary, ($pad ? $this->hexSize : 0));
        }
    }

    /**
     * Validates input data.
     *
     * @param string $input
     * @param string $base
     *
     * @throws InvalidArgumentException If provided invalid type.
     */
    private function _validateInput($input, $base)
    {
        if (!array_key_exists($base, self::$allowedBases)) {
            throw new InvalidArgumentException(sprintf(
                'Type must be one of "%s".',
                implode(', ', array_keys(self::$allowedBases))
            ));
        }

        if (preg_match(self::$allowedBases[$base], $input) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'Input data does not match pattern "%s".',
                self::$allowedBases[$base]
            ));
        }
    }

    /**
     * Validates initialization vector.
     *
     * @param string|null $iv
     */
    private function _validateIv($iv = null)
    {
        if (self::$allowedCiphers[$this->cipher]['iv']) {
            $this->blockSize = openssl_cipher_iv_length($this->cipher);

            $ivLength = mb_strlen($iv, '8bit');
            if ($ivLength !== $this->blockSize) {
                throw new InvalidArgumentException(sprintf(
                    'Initialization vector of %d bytes is required for cipher "%s", %d given.',
                    $this->blockSize,
                    $this->cipher,
                    $ivLength
                ));
            }
        }
    }

    /**
     * Hashes the password.
     *
     * @param string|null $password
     *
     * @return string
     */
    private function _hashPassword($password = null)
    {
        if (null !== $password) {
            $this->password = md5($password);
        }

        return $this->password;
    }

    /**
     * Generates hash keys.
     *
     * @param string|null $hashPassword
     * @param string|null $iv
     *
     * @return array
     */
    private function _roundKeys($hashPassword = null, $iv = null)
    {
        $roundKeys = [];
        $prevKey = $this->_encrypt($this->key, $hashPassword, $iv);
        for ($i = 1; $i <= $this->rounds; $i++) {
            $prevKey = $this->_encrypt($prevKey, $hashPassword, $iv);
            $roundKeys[$i] = substr(DataConverter::rawToBin($prevKey), -1 * $this->sideSize);
        }

        return $roundKeys;
    }
}