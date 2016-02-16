# Cryptomute

A small PHP class implementing Format Preserving Encryption via Feistel Network.

## Installation

You can install Cryptomute via [Composer](http://getcomposer.org) (packagist has [loostro/cryptomute](https://packagist.org/packages/loostro/cryptomute) package). In your `composer.json` file use:

``` json
{
    "require": {
        "loostro/cryptomute": "^1.0"
    }
}
```

And run: `php composer.phar install`. After that you can require the autoloader and use Cryptomute:

## Usage

``` php
require_once 'vendor/autoload.php';

use Cryptomute\Cryptomute;

$cryptomute = new Cryptomute(
    '0',                // minimum value
    '999999999',        // maximum value
    'aes-128-cbc',      // cipher
    '0123456789zxcvbn', // base key
    7,                  // number of rounds
);

$password = '0123456789qwerty';
$iv = '0123456789abcdef';

$plainValue = '2048';
$encoded = $cryptomute->encrypt($plainValue, 10, false, $password, $iv);
$decoded = $cryptomute->decrypt($encoded, 10, false, $password, $iv);

var_dump([
  'plainValue' => $plainValue,
  'encoded'    => $encoded,
  'decoded'    => $decoded,
]);
```

```
array(3) {              
  ["plainValue"]=>       
  string(4) "2048"       
  ["encoded"]=>          
  string(9) "309034283"  
  ["decoded"]=>          
  string(4) "2048"       
}                        
```
	
## Constructor arguments

* `minValue` string representation of minimum value, eg.for domain 0-9999 (4 digit integers) we set it to `0`
* `maxValue` string representation of maximum value, eg.for domain 0-9999 (4 digit integers) we set it to `9999`
* `cipher` the first version supports only `aes-128-cbc`, soon other openssl cipher methods will be added
* `key` base key from which round keys are derrived
* `rounds` number of rounds used, minimum - 3, recommended for stronger security - 7

## License

Cryptomute is licensed under [The MIT License (MIT)](LICENSE).
