# `Bcrypt.php`

**Forked (from myself) at [BitBucket][Original Bcrypt.php].**

[Original Bcrypt.php]: https://bitbucket.org/eddieantonio/bcrypt.php

This is my personal Bcrypt wrapper class-thing I use in my projects for
Bcrypting buisness. It was mostly not written by me -- check the file
comment in the file for all the peeps I attribute this file to. That
said, a quick check on the internet shows a bajillion and one files
*exactly* like this one, all with different names. THE PEOPLE'S BCRYPT
MINILIBRARY... THING.

**Use at your own risk. I offer absolutely no warranty on the
cryptographic amazingness of this library, nor do any of the original
authors... probably.**

# Usage

Use the convenience functions to do some simple hashing and verifying
of hashes.

```php

$hashed = \Bcrypt\hash('this is a random string');

// elsewhere...

$plain_text_password = //... 

if (\Bcrypt\verify($plain_text_password, $user_pass_hash)) {
  login();
}
```

For more fine-grained control, instantiate a `Bcrypt` object:

```php

// Control the prefix, number of rounds...
$bcrypt = new \Bcrypt\Bcrypt('prefix', 15);

// And use the instance to produce many hashes.
$hashes[] = $bcrypt->hash('this is a string');
$hashes[] = $bcrypt->hash('this is another string');

// You can also do this:

if ($bcrypt->verify($plain_text_password, $user_pass_hash)) {
  login();
}
```

## Composer

If you're using Composer, you can just add this to your require list:

```json
{
    "require": {
        "eddieantonio/bcrypt": "0.3.0"
    }
}
```

# License

Public domain.

Since the meat of this code was stolen from various sources who simply
posted the code on the internet with no license, I consider this
library to be public domain by default and take no credit in writing
it; simply polishing it up such that it can be easily used with
Composer.

