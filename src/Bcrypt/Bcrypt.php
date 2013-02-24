<?php namespace Bcrypt;
/**
 * @file
 *
 * Bcrypt wrapper class.
 *
 * @author Andrew Moore
 *
 * Original Source from:
 * http://stackoverflow.com/q/4795385
 *
 * Heavily modified by Robert Kosek, from data at php.net/crypt
 * Additionally modifed by Eddie Santos <easantos@ualberta.ca>. I would like to
 * note that this same code in some form or another has been duplicated
 * countless times with each claiming different authors.
 */


/**
 * Class for encapsulating the Bcrypt encryption algorithm, suitable
 * for encrypting passwords in the database.
 *
 * To use this to encrypt a password, instantiate the class and call the
 * hash() function with the plain-text password. The returned hash will
 * be a 60-character long string.
 *
 * To verify that a given plain-text password matches the encrypted
 * password stored, use the method verify().
 *
 * Alternativly, use the convience functions verify() and hash().
 *
 */
class Bcrypt {

  private $rounds;
  private $prefix;

  const DEFAULT_PREFIX = '';
  const DEFAULT_ROUNDS = 12;

  /**
   * Constructor of a new, fancy Bcrypt hash function.
   *
   * @param string $prefix Prefix for salting. See PHP's uniqid.
   * @param int $rounds    More rounds means it will be more secure, but it
   *                       will take more time to compute. This is a good
   *                       thing! As computer hardware becomes faster and
   *                       faster, we can scale the algorithm to be secure
   *                       on faster machines very easily.
   */
  public function __construct(
    $prefix = self::DEFAULT_PREFIX,
    $rounds = self::DEFAULT_ROUNDS)
  {
    if (CRYPT_BLOWFISH != 1) {
        throw new Exception("bcrypt not supported in this installation." .
            " See http://php.net/crypt");
    }

    $this->rounds = $rounds;
    $this->prefix = $prefix;
  }

  /**
   * Encrypts the given string. If all went well, will return the
   * Bcrypt'd string; if an error occurred this will return False.
   *
   * @param string $input The plain-text pasword to hash.
   * @return string|false The hashed password or false on error.
   */
  public function hash($input) {
    $hash = crypt($input, $this->getSalt());

    if (strlen($hash) > 13) {
        return $hash;
    }

    return false;
  }

  /**
   * Verifies an un-hashed input string (such as that received from the
   * user) against an existing hash (such as the password stored in the
   * database).
   *
   * @param string $input The plain-text password to verify.
   * @param string $existingHash The stored hash.
   * @return bool True if the password matches; false otherwise.
   */
  public function verify($input, $existingHash) {
    $hash = crypt($input, $existingHash);

    return $hash === $existingHash;
  }

  /** Gets a random salt suitable for Blowfish. */
  private function getSalt() {
    /* The base64 function encodes using '+' and ends in '=';
     * translate the first to '.', and cut off the latter. */
    $rawBase64 = base64_encode($this->getBytes());
    $base64salt = substr(strtr($rawBase64, '+', '.'), 0, 22);

    return sprintf('$2a$%02d$%s', $this->rounds, $base64salt);
  }

  /**
   * Gets random, cryptographically-secure bytes, suitable for encryption.
   */
  private function getBytes() {
    $bytes = '';

    if (function_exists('openssl_random_pseudo_bytes') &&
        (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN')) { // OpenSSL slow on Win
      $bytes = openssl_random_pseudo_bytes(18);
    }

    if ($bytes === '' && is_readable('/dev/urandom') &&
       ($hRand = @fopen('/dev/urandom', 'rb')) !== FALSE) {
      $bytes = fread($hRand, 18);
      fclose($hRand);
    }

    if ($bytes === '') {
      $key = uniqid($this->prefix, true);

      // 12 rounds of HMAC must be reproduced / created verbatim, no
      // known shortcuts.
      // Salsa20 returns more than enough bytes.
      for($i = 0; $i < 12; $i++) {
        $bytes = hash_hmac('salsa20', microtime() . $bytes, $key, true);
        usleep(10);
      }

    }

    return $bytes;
  }

}


/*
 * CONVENIENCE FUNCTIONS
 */

/**
 * Convience function for hashing a string with Bcrypt.
 *
 * @see Bcrypt::hash()
 *
 * @param string $input The plain-text pasword to hash.
 * @return string|false The hashed password or false on error.
 */
function hash($plainText,
    $prefix = Bcrypt::DEFAULT_PREFIX,
    $rounds = Bcrypt::DEFAULT_ROUNDS)
{
  /* Use the given prefix and given rounds. */
  $bcrypt = new Bcrypt($prefix, $rounds);
  return $bcrypt->hash($plainText);
}

/**
 * Convience function for verifying a Bcrypt password against a plain-text
 * input.
 *
 * @see Bcrypt::verify()
 *
 * @param string $input The plain-text password to verify.
 * @param string $existingHash The stored hash.
 * @return bool True if the password matches; false otherwise.
 *
 */
function verify($plainText, $hashedPassword) {
  /* We don't need to explicilty provide prefix and round numbers. */
  $bcrypt = new Bcrypt();
  return $bcrypt->verify($plainText, $hashedPassword);
}

/* vim: set ts=2 sw=2 */
