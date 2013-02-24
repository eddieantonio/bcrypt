#!/usr/bin/env php
<?php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../vendor/vierbergenlars/simpletest/autorun.php';

/**
 * Tests for Bcrypt.
 *
 * Since we're testing an algorithm that's *supposed to be slow*, these tests 
 * may take a while.
 *
 * I DO NOT GUARANTEE THAT THESE TESTS ARE EXHAUSTIVE!
 */

class BcryptTests extends UnitTestCase {

  /* Test the Bcrypt class itself. */
  function testBcryptClass() {

    /* Simple Bcrypt with default prefix, rounds. */
    $bcrypt = new \Bcrypt\Bcrypt();

    $sameString = 'arbitrary string contents';

    /* Produce one hash with this string. */
    $hash1 = $bcrypt->hash($sameString);

    /* Assume nothing went wrong. */
    $this->assertIsA($hash1, 'string');
    /* The output should be approximately 60 characters long. */
    $this->assertEqual(strlen($hash1), 60);

    /* Hash that string again. */
    $hash2 = $bcrypt->hash($sameString);
    
    /* The salts should differ, thereby making a different hash. These should 
     * not be the same! */
    $this->assertNotEqual($hash1, $hash2);

    /* Now test if verify works. */
    $this->assertTrue($bcrypt->verify($sameString, $hash1));
    $this->assertTrue($bcrypt->verify($sameString, $hash2));

    /* Now try a different string. */
    $oneExtraChar = $sameString . ' ';
    $oneLessChar = substr($sameString, 1);
    $similarString = strtoupper($sameString);

    $this->assertFalse($bcrypt->verify($oneExtraChar, $hash1));
    $this->assertFalse($bcrypt->verify($oneLessChar, $hash1));
    $this->assertFalse($bcrypt->verify($similarString, $hash1));

  }

  function testConveienceFunctions() {

    $sameString = 'a different, arbitrary string.';

    $hash1 = \Bcrypt\hash($sameString);

    /* Do the usual tests... */
    $this->assertIsA($hash1, 'string');
    $this->assertEqual(strlen($hash1), 60);
    $this->assertTrue(\Bcrypt\verify($sameString, $hash1));

    $differentString = $sameString . ' ';
    $this->assertFalse(\Bcrypt\verify($differentString, $hash1));

  }

}
