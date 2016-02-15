<?php

namespace Cryptomute\Tests;

use Cryptomute\Cipher;
use Cryptomute\Cryptomute;
use PHPUnit_Framework_TestCase;

class CryptomuteTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var Cryptomute
     */
    protected $cryptomute;

    /**
     * @var string
     */
    protected $maxValue;

    public function setUp()
    {
        $this->maxValue = '9999999999';
        $cipher = 'aes-128-cbc';
        $password = openssl_random_pseudo_bytes(32);
        $key = openssl_random_pseudo_bytes(32);
        $rounds = 7;
        $iv = openssl_random_pseudo_bytes(16);

        $this->cryptomute = new Cryptomute($this->maxValue, $cipher, $password, $key, $rounds, $iv);
    }

    public function testReadmeExample()
    {
        $cryptomute = new Cryptomute(
            '999999999',        // maximum value
            'aes-128-cbc',      // cipher
            '0123456789qwerty', // password
            '0123456789zxcvbn', // key
            7,                  // number of rounds
            '0123456789abcdef'  // initialization vector
        );

        $plainValue = '2048';
        $encoded = $cryptomute->encrypt($plainValue, 'dec');
        $decoded = $cryptomute->decrypt($encoded, 'dec');

        $this->assertEquals($plainValue, $decoded);
    }

    public function testEncodedValuesAreInDomain()
    {
        $domain = '999';
        $cryptomute = new Cryptomute(
            $domain,            // maximum value
            'aes-128-cbc',      // cipher
            '0123456789qwerty', // password
            '0123456789zxcvbn', // key
            7,                  // number of rounds
            '0123456789abcdef'  // initialization vector
        );

        $message = 'Value %s encoded to %s is still in domain %s.';

        for ($i = 0; $i <= 999; $i++) {
            $plainValue = "$i";
            $encoded = $cryptomute->encrypt($plainValue, 'dec');

            $this->assertFalse(intval($encoded) > 999, sprintf($message, $plainValue, $encoded, $domain));
        }
    }

    public function testDecodesEncodedBinaryNumbers()
    {
        for ($i = 0; $i < 10; $i++) {
            $input = gmp_strval(gmp_random_range(
                gmp_init('0', 10),
                gmp_init($this->maxValue, 10)
            ), 2);

            $encrypted = $this->cryptomute->encrypt($input, 'bin');
            $decrypted = $this->cryptomute->decrypt($encrypted, 'bin');

            $this->assertEquals($input, $decrypted, sprintf(
                'Encoded binary value must decode to initial value [%s].',
                $input
            ));
        }
    }

    public function testDecodesEncodedDecimalNumbers()
    {
        for ($i = 0; $i < 10; $i++) {
            $input = gmp_strval(gmp_random_range(
                gmp_init('0', 10),
                gmp_init($this->maxValue, 10)
            ), 10);

            $encrypted = $this->cryptomute->encrypt($input, 'dec');
            $decrypted = $this->cryptomute->decrypt($encrypted, 'dec');

            $this->assertEquals($input, $decrypted, sprintf(
                'Encoded decimal value must decode to initial value [%s].',
                $input
            ));
        }
    }

    public function testDecodesEncodedHexadecimalNumbers()
    {
        for ($i = 0; $i < 10; $i++) {
            $input = gmp_strval(gmp_random_range(
                gmp_init('0', 10),
                gmp_init($this->maxValue, 10)
            ), 16);

            $encrypted = $this->cryptomute->encrypt($input, 'hex');
            $decrypted = $this->cryptomute->decrypt($encrypted, 'hex');

            $this->assertEquals($input, $decrypted, sprintf(
                'Encoded decimal value must decode to initial value [%s].',
                $input
            ));
        }
    }
}
