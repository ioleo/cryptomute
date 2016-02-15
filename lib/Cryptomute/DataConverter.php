<?php

namespace Cryptomute;

/**
 * Cryptomute
 *
 * (c) 2016 Piotr Gołębiewski
 *
 * Released under MIT license.
 * https://github.com/loostro/cryptomute
 *
 * Helper class converting data from/to various formats.
 */
class DataConverter
{
    /**
     * Converts binary string into decimal string.
     *
     * @param string $bin    Binary string.
     * @param int    $length Minimum output length.
     *
     * @return string Decimal string.
     */
    public static function binToDec($bin, $length = 0)
    {
        $gmp = gmp_init($bin, 2);
        $dec = gmp_strval($gmp, 10);

        return self::pad($dec, $length);
    }

    /**
     * Converts binary string into hexadecimal string.
     *
     * @param string $bin    Binary string.
     * @param int    $length Minimum output length.
     *
     * @return string Hexadecimal string.
     */
    public static function binToHex($bin, $length = 0)
    {
        $gmp = gmp_init($bin, 2);
        $hex = gmp_strval($gmp, 16);

        return self::pad($hex, $length);
    }

    /**
     * Converts binary string into stream of bytes.
     *
     * @param string $bin Binary string.
     *
     * @return mixed Stream of bytes.
     */
    public static function binToRaw($bin)
    {
        $gmp = gmp_init($bin, 2);

        return gmp_export($gmp);
    }

    /**
     * Converts decimal string into binary string.
     *
     * @param string $dec    Decimal string.
     * @param int    $length Minimum output length.
     *
     * @return string Binary string.
     */
    public static function decToBin($dec, $length = 0)
    {
        $gmp = gmp_init($dec, 10);
        $bin = gmp_strval($gmp, 2);

        return self::pad($bin, $length);
    }

    /**
     * Converts decimal string into hexadecimal string.
     *
     * @param string $dec    Decimal string.
     * @param int    $length Minimum output length.
     *
     * @return string Hexadecimal string.
     */
    public static function decToHex($dec, $length = 0)
    {
        $gmp = gmp_init($dec, 10);
        $hex = gmp_strval($gmp, 16);

        return self::pad($hex, $length);
    }

    /**
     * Converts decimal string into stream of bytes.
     *
     * @param string $dec Decimal string.
     *
     * @return mixed Stream of bytes.
     */
    public static function decToRaw($dec)
    {
        $gmp = gmp_init($dec, 10);

        return gmp_export($gmp);
    }

    /**
     * Converts hexadecimal string into binary string.
     *
     * @param string $hex    Hexadecimal string.
     * @param int    $length Minimum output length.
     *
     * @return string Binary string.
     */
    public static function hexToBin($hex, $length = 0)
    {
        $gmp = gmp_init($hex, 16);
        $bin = gmp_strval($gmp, 2);

        return self::pad($bin, $length);
    }

    /**
     * Converts hexadecimal string into decimal string.
     *
     * @param string $hex    Hexadecimal string.
     * @param int    $length Minimum output length.
     *
     * @return string Decimal string.
     */
    public static function hexToDec($hex, $length = 0)
    {
        $gmp = gmp_init($hex, 16);
        $dec = gmp_strval($gmp, 10);

        return self::pad($dec, $length);
    }

    /**
     * Converts hexadecimal string into stream of bytes.
     *
     * @param string $hex Hexadecimal string.
     *
     * @return mixed Stream of bytes.
     */
    public static function hexToRaw($hex)
    {
        $gmp = gmp_init($hex, 16);

        return gmp_export($gmp);
    }

    /**
     * Converts stream of bytes into binary string.
     *
     * @param mixed $raw    Stream of bytes.
     * @param int   $length Minimum output length.
     *
     * @return string Binary string.
     */
    public static function rawToBin($raw, $length = 0)
    {
        $gmp = gmp_import($raw);
        $bin = gmp_strval($gmp, 2);

        return self::pad($bin, $length);
    }

    /**
     * Converts stream of bytes into decimal string.
     *
     * @param mixed $raw    Stream of bytes.
     * @param int   $length Minimum output length.
     *
     * @return string Decimal string.
     */
    public static function rawToDec($raw, $length = 0)
    {
        $gmp = gmp_import($raw);
        $dec = gmp_strval($gmp, 10);

        return self::pad($dec, $length);
    }

    /**
     * Converts stream of bytes into hexadecimal string.
     *
     * @param mixed $raw    Stream of bytes.
     * @param int   $length Minimum output length.
     *
     * @return string Hex string.
     */
    public static function rawToHex($raw, $length = 0)
    {
        $gmp = gmp_import($raw);
        $hex = gmp_strval($gmp, 16);

        return self::pad($hex, $length);
    }

    /**
     * Pad left with zeroes to match given length.
     *
     * @param string $input
     * @param int    $length
     *
     * @return string
     */
    public static function pad($input, $length = 0)
    {
        $input = ltrim($input, '0');

        if ($input == '') {
            $input = '0';
        }

        return str_pad($input, $length, '0', STR_PAD_LEFT);
    }
}