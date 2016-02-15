<?php


namespace Cryptomute\Tests;

use Cryptomute\DataConverter;
use PHPUnit_Framework_TestCase;

/**
 * Tests if helper methods correctly convert values.
 *
 * @coversDefaultClass Cryptomute\DataConverter
 *
 * @author Piotr Gołębiewski <cryptomute@gmail.pl>
 */
class DataConverterTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var array
     */
    public static $convertData;

    /**
     * Sets test data.
     */
    public static function setUpBeforeClass()
    {
        self::$convertData = [
            '2-digit integer' => [
                'decimal'     => '10',
                'hexadecimal' => 'a',
                'binary'      => '1010',
                'raw'         => gmp_export(gmp_init('10', 10)),
            ],
            '3-digit integer' => [
                'decimal'     => '123',
                'hexadecimal' => '7b',
                'binary'      => '1111011',
                'raw'         => gmp_export(gmp_init('123', 10)),
            ],
            '4-digit integer' => [
                'decimal'     => '3328',
                'hexadecimal' => 'd00',
                'binary'      => '110100000000',
                'raw'         => gmp_export(gmp_init('3328', 10)),
            ],
            '32-bit signed integer max value'  => [
                'decimal'     => '2147483647',
                'hexadecimal' => '7'.str_repeat('f', 7),
                'binary'      => str_repeat('1', 31),
                'raw'         => gmp_export(gmp_init('2147483647', 10)),
            ],
            '64-bit signed integer max value'  => [
                'decimal'     => '9223372036854775807',
                'hexadecimal' => '7'.str_repeat('f', 15),
                'binary'      => str_repeat('1', 63),
                'raw'         => gmp_export(gmp_init('9223372036854775807', 10)),
            ],
            '128-bit signed integer max value' => [
                'decimal'     => '170141183460469231731687303715884105727',
                'hexadecimal' => '7'.str_repeat('f', 31),
                'binary'      => str_repeat('1', 127),
                'raw'         => gmp_export(gmp_init('170141183460469231731687303715884105727', 10)),
            ],
        ];
    }

    /**
     * @covers ::pad
     */
    public function testPaddedValue()
    {
        $testData = [
            '1010'     => [0 => '1010',     3 => '1010',     8 => '00001010'],
            '12345678' => [0 => '12345678', 3 => '12345678', 8 => '12345678'],
            '001122'   => [0 => '1122',     3 => '1122',     8 => '00001122'],
            '0000'     => [0 => '0',        3 => '000',      8 => '00000000'],
        ];

        $message = 'Input %s padded left to %d length should output %s.';
        foreach ($testData as $input => $tests) {
            foreach($tests as $length => $expected) {
                $result = DataConverter::pad($input, $length);

                $this->assertEquals($expected, $result, sprintf($message, $input, $length, $expected));
            }
        }
    }

    /**
     * @covers ::binToDec
     */
    public function testConvertingFromBinToDec()
    {
        foreach (self::$convertData as $name => $data) {
            $binary = $data['binary'];
            $decimal = $data['decimal'];

            $msg = 'Convert "%s" from binary to decimal form.';
            $result = DataConverter::binToDec($binary);

            $this->assertEquals($decimal, $result, sprintf($msg, $name));
        }
    }

    /**
     * @covers ::binToHex
     */
    public function testConvertingFromBinToHex()
    {
        foreach (self::$convertData as $name => $data) {
            $binary = $data['binary'];
            $hexadecimal = $data['hexadecimal'];

            $msg = 'Convert "%s" from binary to hexadecimal form.';
            $result = DataConverter::binToHex($binary);

            $this->assertEquals($hexadecimal, $result, sprintf($msg, $name));
        }
    }

    /**
     * @covers ::binToRaw
     */
    public function testConvertingFromBinToRaw()
    {
        foreach (self::$convertData as $name => $data) {
            $binary = $data['binary'];
            $raw = $data['raw'];

            $msg = 'Convert "%s" from binary to raw form.';
            $result = DataConverter::binToRaw($binary);

            $this->assertEquals($raw, $result, sprintf($msg, $name));
        }
    }

    /**
     * @covers ::decToBin
     */
    public function testConvertingFromDecToBin()
    {
        foreach (self::$convertData as $name => $data) {
            $decimal = $data['decimal'];
            $binary = $data['binary'];

            $msg = 'Convert "%s" from decimal to binary form.';
            $result = DataConverter::decToBin($decimal);

            $this->assertEquals($binary, $result, sprintf($msg, $name));
        }
    }

    /**
     * @covers ::decToHex
     */
    public function testConvertingFromDecToHex()
    {
        foreach (self::$convertData as $name => $data) {
            $decimal = $data['decimal'];
            $hexadecimal = $data['hexadecimal'];

            $msg = 'Convert "%s" from decimal to hexadecimal form.';
            $result = DataConverter::decToHex($decimal);

            $this->assertEquals($hexadecimal, $result, sprintf($msg, $name));
        }
    }

    /**
     * @covers ::decToRaw
     */
    public function testConvertingFromDecToRaw()
    {
        foreach (self::$convertData as $name => $data) {
            $decimal = $data['decimal'];
            $raw = $data['raw'];

            $msg = 'Convert "%s" from decimal to raw form.';
            $result = DataConverter::decToRaw($decimal);

            $this->assertEquals($raw, $result, sprintf($msg, $name));
        }
    }

    /**
     * @covers ::hexToBin
     */
    public function testConvertingFromHexToBin()
    {
        foreach (self::$convertData as $name => $data) {
            $hexadecimal = $data['hexadecimal'];
            $binary = $data['binary'];

            $msg = 'Convert "%s" from hexadecimal to binary form.';
            $result = DataConverter::hexToBin($hexadecimal);

            $this->assertEquals($binary, $result, sprintf($msg, $name));
        }
    }

    /**
     * @covers ::hexToDec
     */
    public function testConvertingFromHexToDec()
    {
        foreach (self::$convertData as $name => $data) {
            $hexadecimal = $data['hexadecimal'];
            $decimal = $data['decimal'];

            $msg = 'Convert "%s" from hexadecimal to decimal form.';
            $result = DataConverter::hexToDec($hexadecimal);

            $this->assertEquals($decimal, $result, sprintf($msg, $name));
        }
    }

    /**
     * @covers ::hexToRaw
     */
    public function testConvertingFromHexToRaw()
    {
        foreach (self::$convertData as $name => $data) {
            $hexadecimal = $data['hexadecimal'];
            $raw = $data['raw'];

            $msg = 'Convert "%s" from hexadecimal to raw form.';
            $result = DataConverter::hexToRaw($hexadecimal);

            $this->assertEquals($raw, $result, sprintf($msg, $name));
        }
    }

    /**
     * @covers ::rawToBin
     */
    public function testConvertingFromRawToBin()
    {
        foreach (self::$convertData as $name => $data) {
            $raw = $data['raw'];
            $binary = $data['binary'];

            $msg = 'Convert "%s" from raw to binary form.';
            $result = DataConverter::rawToBin($raw);

            $this->assertEquals($binary, $result, sprintf($msg, $name));
        }
    }

    /**
     * @covers ::rawToDec
     */
    public function testConvertingFromRawToDec()
    {
        foreach (self::$convertData as $name => $data) {
            $raw = $data['raw'];
            $decimal = $data['decimal'];

            $msg = 'Convert "%s" from raw to decimal form.';
            $result = DataConverter::rawToDec($raw);

            $this->assertEquals($decimal, $result, sprintf($msg, $name));
        }
    }

    /**
     * @covers ::rawToHex
     */
    public function testConvertingFromRawToHex()
    {
        foreach (self::$convertData as $name => $data) {
            $raw = $data['raw'];
            $hexadecimal = $data['hexadecimal'];

            $msg = 'Convert "%s" from raw to hexadecimal form.';
            $result = DataConverter::rawToHex($raw);

            $this->assertEquals($hexadecimal, $result, sprintf($msg, $name));
        }
    }
}