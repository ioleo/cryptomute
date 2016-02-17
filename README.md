# Cryptomute

A small PHP class implementing Format Preserving Encryption via Feistel Network.

## 1. Installation

You can install Cryptomute via [Composer](http://getcomposer.org) (packagist has [loostro/cryptomute](https://packagist.org/packages/loostro/cryptomute) package). In your `composer.json` file use:

``` json
{
    "require": {
        "loostro/cryptomute": "^1.0"
    }
}
```

And run: `php composer.phar install`. After that you can require the autoloader and use Cryptomute:

## 2. Usage

``` php
require_once 'vendor/autoload.php';

use Cryptomute\Cryptomute;

$cryptomute = new Cryptomute(
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
	
## 3. Options

### 3.1 Cipher
 
Cipher is the first constructor argument. Supported cipher methods are:

Cipher             | IV
------------------ | ---
`des-cbc`          | yes
`aes-128-cbc`      | yes
`aes-128-ecb`      | no
`aes-192-cbc`      | yes
`aes-192-ecb`      | no
`camellia-128-cbc` | yes
`camellia-128-ecb` | no
`camellia-192-cbc` | yes
`camellia-192-ecb` | no

### 3.2 Key

Key is the second constructor argument. Base key from which all round keys are derrived.

### 3.3 Rounds

Rounds is the third constructor argument. Must be an odd integer greater or equal to 3. More rounds is more secure,
but also slower. Recommended value is at least 7.

## 4. Public methods

### 4.1 setValueRange(`$minValue`, `$maxValue`)

Sets minimum and maximum values. If the result is out of range it will be re-encrypted (or re-decrypted) until ouput
is in range.

### 4.2 encrypt(`$plainValue`, `$base`, `$pad`, `$password`, `$iv`)
 
Encrypts data. Takes following arguments:

* `$plainValue` (string) input data to be encrypted
* `$base` (int) input data base, accepted values is 2 (binary), 10 (decimal) or 16 (hexadecimal)
* `$pad` (bool) pad left output to match `$maxValue`'s length?
* `$password` (string) encryption password
* `$iv` (string) initialization vector - only if cipher requires it


### 4.2 decrypt(`$cryptValue`, `$base`, `$pad`, `$password`, `$iv`)
 
Decrypts data. Takes following arguments:

* `$cryptValue` (string) input data to be decrypted
* `$base` (int) input data base, accepted values is 2 (binary), 10 (decimal) or 16 (hexadecimal)
* `$pad` (bool) pad left output to match `$maxValue`'s length?
* `$password` (string) encryption password
* `$iv` (string) initialization vector - only if cipher requires it

## License

Cryptomute is licensed under [The MIT License (MIT)](LICENSE).
