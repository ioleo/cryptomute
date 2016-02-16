<?php

namespace Cryptomute\Tests;

use Cryptomute\Cipher;
use Cryptomute\Cryptomute;
use PHPUnit_Framework_TestCase;

class CryptomuteTest extends PHPUnit_Framework_TestCase
{
    const MIN_VALUE = '0';
    const MAX_VALUE = '9999999999';
    const CIPHER = 'aes-128-cbc';

    public static $testedRounds = [
        3  => 'minimum',
        5  => 'normal',
        7  => 'recommended',
        11 => 'insane',
    ];

    public function testReadmeExample()
    {
        $message = '[%d / %s] Expected README example to work.';

        foreach (self::$testedRounds as $rounds => $description) {
            $cryptomute = $this->getCryptomute($rounds);
            $password = openssl_random_pseudo_bytes(32);
            $iv = openssl_random_pseudo_bytes(16);

            $plainValue = '2048';
            $encoded = $cryptomute->encrypt($plainValue, 10, false, $password, $iv);
            $decoded = $cryptomute->decrypt($encoded, 10, false, $password, $iv);

            $this->assertEquals($plainValue, $decoded, sprintf(
                $message,
                $rounds,
                $description
            ));
        }
    }

    public function testEncodedValuesAreInDomain()
    {
        $message = '[%d / %s] Base %d value of %s encoded to %s is still in domain %s - %s.';
        $minVal = 100;
        $maxVal = 999;

        foreach (self::$testedRounds as $rounds => $description) {
            $cryptomute = $this->getCryptomute($rounds, "$minVal", "$maxVal");
            $password = openssl_random_pseudo_bytes(32);

            foreach (Cryptomute::$allowedBases as $base => $pattern) {
                for ($i = $minVal; $i <= $maxVal; $i++) {
                    $iv = openssl_random_pseudo_bytes(16);

                    $input = gmp_strval(gmp_init("$i", 10), $base);
                    $encoded = $cryptomute->encrypt($input, $base, false, $password, $iv);
                    $intVal = (int)gmp_strval(gmp_init($encoded, $base), 10);

                    $this->assertTrue(
                        $minVal <= $intVal && $intVal <= $maxVal,
                        sprintf($message, $rounds, $description, $base, $i, $encoded, $minVal, $maxVal)
                    );
                }
            }
        }
    }

    public function testDecodesEncodedNumbers()
    {
        $message = '[%d / %s] Encoded base %d value must decode to initial value [%s].';

        foreach (self::$testedRounds as $rounds => $description) {
            $cryptomute = $this->getCryptomute($rounds);
            $password = openssl_random_pseudo_bytes(32);

            foreach (Cryptomute::$allowedBases as $base => $pattern) {
                for ($i = 0; $i < 10; $i++) {
                    $iv = openssl_random_pseudo_bytes(16);

                    $input = gmp_strval(gmp_random_range(
                        gmp_init(self::MIN_VALUE, 10),
                        gmp_init(self::MAX_VALUE, 10)
                    ), $base);

                    $encrypted = $cryptomute->encrypt($input, $base, false, $password, $iv);
                    $decrypted = $cryptomute->decrypt($encrypted, $base, false, $password, $iv);

                    $this->assertEquals($input, $decrypted, sprintf(
                        $message,
                        $rounds,
                        $description,
                        $base,
                        $input
                    ));
                }
            }
        }
    }

    public function testEncodeWithDiffrentPasswordsProducesDiffrentResults()
    {
        $message = '[%d / %s] Same base %d value encoded with diffrent passwords produce diffrent results [%s].';

        foreach (self::$testedRounds as $rounds => $description) {
            $cryptomute = $this->getCryptomute($rounds);

            foreach (Cryptomute::$allowedBases as $base => $pattern) {
                for ($i = 0; $i < 10; $i++) {
                    $iv = openssl_random_pseudo_bytes(16);

                    $input = gmp_strval(gmp_random_range(
                        gmp_init(self::MIN_VALUE, 10),
                        gmp_init(self::MAX_VALUE, 10)
                    ), $base);

                    $encrypted1 = $cryptomute->encrypt($input, $base, false, 'foo', $iv);
                    $encrypted2 = $cryptomute->encrypt($input, $base, false, 'bar', $iv);

                    $this->assertNotEquals($encrypted1, $encrypted2, sprintf(
                        $message,
                        $rounds,
                        $description,
                        $base,
                        $input
                    ));
                }
            }
        }
    }

    public function testDecodeWithDiffrentPasswordsProducesDiffrentResults()
    {
        $message = '[%d / %s] Same base %d value decoded with diffrent passwords produce diffrent results [%s].';

        foreach (self::$testedRounds as $rounds => $description) {
            $cryptomute = $this->getCryptomute($rounds);

            foreach (Cryptomute::$allowedBases as $base => $pattern) {
                for ($i = 0; $i < 10; $i++) {
                    $iv = openssl_random_pseudo_bytes(16);

                    $input = gmp_strval(gmp_random_range(
                        gmp_init(self::MIN_VALUE, 10),
                        gmp_init(self::MAX_VALUE, 10)
                    ), $base);

                    $decrypted1 = $cryptomute->decrypt($input, $base, false, 'foo', $iv);
                    $decrypted2 = $cryptomute->decrypt($input, $base, false, 'bar', $iv);

                    $this->assertNotEquals($decrypted1, $decrypted2, sprintf(
                        $message,
                        $rounds,
                        $description,
                        $base,
                        $input
                    ));
                }
            }
        }
    }

    /**
     * @param int         $rounds
     * @param string|null $minVal
     * @param string|null $maxVal
     *
     * @return Cryptomute
     */
    private function getCryptomute($rounds, $minVal = null, $maxVal = null)
    {
        return new Cryptomute(
            $minVal ?: self::MIN_VALUE,
            $maxVal ?: self::MAX_VALUE,
            self::CIPHER,
            openssl_random_pseudo_bytes(32),
            $rounds
        );
    }
}
