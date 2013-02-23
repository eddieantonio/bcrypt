# `Bcrypt.php`

**Forked (from myself) at [BitBucket][Original Bcrypt.php]**

[Original Bcrypt.php]: https://bitbucket.org/eddieantonio/bcrypt.php

This is my personal Bcrypt wrapper class-thing I use in my projects for
Bcrypting buisness. It was mostly not written by me -- check the file
comment in the file for all the peeps I attribute this file to. That
said, a quick check on the internet shows a bajillion and one files
*exactly* like this one, all with different names. THE PEOPLE'S BCRYPT
MINILIBRARY... THING.

Use at your own risk. I offer absolutely no warranty on the
cryptographic amazingness of this library, nor do any of the original
authors... probably.

# Usage

Simply instantiate and Bcrypt to your heart's desire!

```php

$bcrypt = new \Bcrypt\Bcrypt();

$hashed = $bcrypt->hash('this is a random string');

// elsewhere...

$plain_text_password = //... 

if ($bcrypt->verify($plain_text_password, $user_pass_hash)) {
  login();
}
```

