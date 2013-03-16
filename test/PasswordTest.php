<?php
/**
* CodeAngel Security Framework
*
* LICENSE
*
* Copyright (c) 2011, Chad Minick
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
*
*    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
*    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
* THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
* PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
* WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
* ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

include "setup.php";

class PasswordTest extends PHPUnit_Framework_TestCase {
    
    public function testDefaultPasswordGenerator() {
        $gen = new org\codeangel\security\passwords\DefaultPasswordGenerator;
        $this->assertTrue($gen instanceof org\codeangel\security\passwords\BlowFishCryptPasswordGenerator, "Default is not a BlowFishCryptPasswordGenerator");
        $password = $gen->genPassword("foobar");
        $this->assertNotEquals($password, 'foobar');
        $this->assertNotEmpty($password);
        $result = $gen->checkPassword('foobar', $password);
        $this->assertTrue($result, "passwords do not match, even though they should");
        $result = $gen->checkPassword('foobar1', $password);
        $this->assertFalse($result, "passwords do match, even though they should not");
    }
    
    public function testBlowFishCryptPasswordGenerator() {
        $gen = new org\codeangel\security\passwords\BlowFishCryptPasswordGenerator;
        $password = $gen->genPassword("foobar");
        $this->assertNotEquals($password, 'foobar');
        $this->assertNotEmpty($password);
        $this->assertStringStartsWith("$2a$", $password);
        $result = $gen->checkPassword('foobar', $password);
        $this->assertTrue($result, "passwords do not match, even though they should");
        $result = $gen->checkPassword('foobar1', $password);
        $this->assertFalse($result, "passwords do match, even though they should not");

        //testing cost
        $gen->setCost(6,6);
        $result = $gen->genPassword("foobar");
        $this->assertStringStartsWith('$2a$06$', $result);
    }
    
    public function testSHA256CryptPasswordGenerator() {
    	$gen = new org\codeangel\security\passwords\Sha256CryptPasswordGenerator;
    	$password = $gen->genPassword("foobar");
    	$this->assertNotEquals($password, 'foobar');
    	$this->assertNotEmpty($password);
    	$this->assertStringStartsWith("$5$", $password);
    	$result = $gen->checkPassword('foobar', $password);
    	$this->assertTrue($result, "passwords do not match, even though they should");
    	$result = $gen->checkPassword('foobar1', $password);
    	$this->assertFalse($result, "passwords do match, even though they should not");

        //test cost
        $gen->setCost(9999,9999);
        $result = $gen->genPassword("foobar");
        $this->assertStringStartsWith('$5$rounds=9999', $result);
    }
    
    public function testSHA512CryptPasswordGenerator() {
    	$gen = new org\codeangel\security\passwords\Sha512CryptPasswordGenerator;
    	$password = $gen->genPassword("foobar");
    	$this->assertNotEquals($password, 'foobar');
    	$this->assertNotEmpty($password);
    	$this->assertStringStartsWith("$6$", $password);
    	$result = $gen->checkPassword('foobar', $password);
    	$this->assertTrue($result, "passwords do not match, even though they should");
    	$result = $gen->checkPassword('foobar1', $password);
    	$this->assertFalse($result, "passwords do match, even though they should not");

        //test cost
        $gen->setCost(9999,9999);
        $result = $gen->genPassword("foobar");
        $this->assertStringStartsWith('$6$rounds=9999', $result);
    }

    public function testKoremetake() {
        $gen = new org\codeangel\security\passwords\KoremutakePassword;
        $this->assertEquals($gen->integerToKoremutake(0), 'ba');
        $this->assertEquals($gen->integerToKoremutake(39), 'ko');
        $this->assertEquals($gen->integerToKoremutake(67), 're');
        $this->assertEquals($gen->integerToKoremutake(52), 'mu');
        $this->assertEquals($gen->integerToKoremutake(78), 'ta');
        $this->assertEquals($gen->integerToKoremutake(37), 'ke');
        $this->assertEquals($gen->integerToKoremutake(128), 'beba');
        $this->assertEquals($gen->integerToKoremutake(256), 'biba');
        $this->assertEquals($gen->integerToKoremutake(65535), 'botretre');
        $this->assertEquals($gen->integerToKoremutake(65536), 'bubaba');
        $this->assertEquals($gen->integerToKoremutake(5059), 'kore');
        $this->assertEquals($gen->integerToKoremutake(10610353957), 'koremutake');

        $this->assertEquals($gen->koremutakeToInteger('ba'), 0);
        $this->assertEquals($gen->koremutakeToInteger('ko'), 39);
        $this->assertEquals($gen->koremutakeToInteger('re'), 67);
        $this->assertEquals($gen->koremutakeToInteger('mu'), 52);
        $this->assertEquals($gen->koremutakeToInteger('ta'), 78);
        $this->assertEquals($gen->koremutakeToInteger('ke'), 37);
        $this->assertEquals($gen->koremutakeToInteger('beba'), 128);
        $this->assertEquals($gen->koremutakeToInteger('biba'), 256);
        $this->assertEquals($gen->koremutakeToInteger('botretre'), 65535);
        $this->assertEquals($gen->koremutakeToInteger('bubaba'), 65536);
        $this->assertEquals($gen->koremutakeToInteger('kore'), 5059);
        $this->assertEquals($gen->koremutakeToInteger('koremutake'), 10610353957);

    }

    /**
     * @expectedException Exception
     */
    public function testkoremutakeFailure() {
        $gen = new org\codeangel\security\passwords\KoremutakePassword;
        $gen->koremutakeToInteger("hello world");
    }

    public function testPronounceable() {
        $gen = new org\codeangel\security\passwords\PronPassword;
        list($word, $pron) = $gen->genPass(20, 20);
        $this->assertEquals(strlen($word), 20);
        $this->assertRegExp('/^[a-z]+$/', $word);
        $this->assertRegExp('/^[a-z-]+$/i', $word);

        for($i = 0; $i < 10; $i ++) {
            list($word, $pron) = $gen->genPass(2, 20);
            $this->assertGreaterThanOrEqual(2, strlen($word));
            $this->assertLessThanOrEqual(20, strlen($word));
            $this->assertRegExp('/^[a-z]+$/', $word);
            $this->assertRegExp('/^[a-z-]+$/i', $word);
        }
    }

    public function testPasswordUtils() {
        $this->assertRegExp('/[A-Z]/', org\codeangel\security\passwords\PasswordUtils::randomCaptilize("hello"));

        //
        $this->assertEquals('hElLo', org\codeangel\security\passwords\PasswordUtils::capitilizeAlternating("hello"));
        $this->assertEquals('HeLlO', org\codeangel\security\passwords\PasswordUtils::capitilizeAlternating("hello", false));

        //
        $this->assertEquals('he110', org\codeangel\security\passwords\PasswordUtils::numerize("hello"));
        $this->assertEquals('h3110', org\codeangel\security\passwords\PasswordUtils::numerize("hello", true));

        //
        $this->assertEquals('the c@t !n the h@t', org\codeangel\security\passwords\PasswordUtils::symbolize("the cat in the hat"));
        $this->assertEquals('t#e c@t !n t#e #@t', org\codeangel\security\passwords\PasswordUtils::symbolize("the cat in the hat", true));

        //
        $this->assertEquals('the c@t !n the h@t', org\codeangel\security\passwords\PasswordUtils::numsymolize("the cat in the hat"));
        $this->assertEquals('7#3 c47 !n 7#3 #47', org\codeangel\security\passwords\PasswordUtils::numsymolize("the cat in the hat", true));
    }


    public function testPasswordStrength() {

        $strength = new org\codeangel\security\passwords\PasswordStrength("hello");

        $this->assertEquals(24, (int)$strength->getEntropy());
        $this->assertEquals(20, $strength->getScore());
        $this->assertFalse($strength->isFoundInDictionary());
        $this->assertEquals(org\codeangel\security\passwords\PasswordStrength::VERY_WEAK, $strength->getStrength());
        $this->assertEquals("very weak", $strength->strengthWord());

        $strength->setPassword('Tr0ub4dor&3');
        $this->assertEquals(69, (int)$strength->getEntropy());
        $this->assertEquals(80, $strength->getScore());
        $this->assertFalse($strength->isFoundInDictionary());
        $this->assertEquals(org\codeangel\security\passwords\PasswordStrength::STRONG, $strength->getStrength());
        $this->assertEquals("strong", $strength->strengthWord());

        $strength->setPassword('correcthorsebatterystaple');
        $this->assertEquals(131, (int)$strength->getEntropy());
        $this->assertEquals(100, $strength->getScore());
        $this->assertFalse($strength->isFoundInDictionary());
        $this->assertEquals(org\codeangel\security\passwords\PasswordStrength::VERY_STRONG, $strength->getStrength());
        $this->assertEquals("very strong", $strength->strengthWord());
    }

    public function testPasswordStrengthWithWordList() {
        if(!file_exists('wordlist.sq3')) {
            return;
        }

        $strength = new org\codeangel\security\passwords\PasswordStrength("hello", new org\codeangel\security\passwords\SqliteWordList('wordlist.sq3'));

        $this->assertEquals(24, (int)$strength->getEntropy());
        $this->assertEquals(20, $strength->getScore());
        $this->assertTrue($strength->isFoundInDictionary());
        $this->assertEquals(org\codeangel\security\passwords\PasswordStrength::VERY_WEAK, $strength->getStrength());
        $this->assertEquals("very weak", $strength->strengthWord());

        $strength->setPassword("0p9o8i7u");
        $this->assertEquals(43, (int)$strength->getEntropy());
        $this->assertEquals(20, $strength->getScore());
        $this->assertTrue($strength->isFoundInDictionary());
        $this->assertEquals(org\codeangel\security\passwords\PasswordStrength::VERY_WEAK, $strength->getStrength());
        $this->assertEquals("very weak", $strength->strengthWord());

        $strength->setPassword('Tr0ub4dor&3');
        $this->assertEquals(69, (int)$strength->getEntropy());
        $this->assertEquals(80, $strength->getScore());
        $this->assertFalse($strength->isFoundInDictionary());
        $this->assertEquals(org\codeangel\security\passwords\PasswordStrength::STRONG, $strength->getStrength());
        $this->assertEquals("strong", $strength->strengthWord());

        $strength->setPassword('correcthorsebatterystaple');
        $this->assertEquals(131, (int)$strength->getEntropy());
        $this->assertEquals(100, $strength->getScore());
        $this->assertFalse($strength->isFoundInDictionary());
        $this->assertEquals(org\codeangel\security\passwords\PasswordStrength::VERY_STRONG, $strength->getStrength());
        $this->assertEquals("very strong", $strength->strengthWord());
    }

    public function testWordList(){
        if(!file_exists('wordlist.sq3')) {
            return;
        }
        $wordlist = new org\codeangel\security\passwords\SqliteWordList('wordlist.sq3');
        $this->assertTrue($wordlist->check('hello'), "Checking if 'hello' is in the wordlist");
        $this->assertFalse($wordlist->check('fsqec'), "Checking if 'fsqec' is not in the wordlist");
    }

    public function testStringCompare() {
        $this->assertTrue(org\codeangel\security\passwords\PasswordUtils::compare('hello', 'hello'));
        $this->assertFalse(org\codeangel\security\passwords\PasswordUtils::compare('hello', 'world'));
    }
}