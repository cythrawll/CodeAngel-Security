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
    }
}
