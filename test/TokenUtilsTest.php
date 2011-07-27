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

class TokenUtilsTest extends PHPUnit_Framework_TestCase {
    
    public function testTokenGenerator() {
        $obj = new org\codeangel\security\TokenUtils();
        $token = $obj->generateToken(22);
        $this->assertEquals(22, strlen($token));
        $this->assertTrue(ctype_alnum($token), "Token is not alpha numeric");
    }
    
    public function testGenerateTokenFromAlphabet() {
    	$obj = new org\codeangel\security\TokenUtils();
    	$token = $obj->generateTokenFromAlphabet(66);
    	$this->assertEquals(66, strlen($token));
    	$this->assertTrue(ctype_alnum($token), "Token is not alpha numeric");
    	
    	$token = $obj->generateTokenFromAlphabet(100, "ab");
    	$this->assertRegExp('#^[ab]+$#', $token);
    	
    	$token = $obj->generateTokenFromAlphabet(100, org\codeangel\security\TokenUtils::ALPHA_NUM.org\codeangel\security\TokenUtils::PRINTABLE_EXTRA);
    	$this->assertRegExp('#^[A-Za-z0-9~.`!@\#$%^&*(){}[\\]\':"\\\/.,|_+=-]+$#', $token);
    }
    
    public function testGenerateCryptBlowfishSalt() {
        $obj = new org\codeangel\security\TokenUtils();
        $token = $obj->generateCryptBlowfishSalt();

        $this->assertEquals(22, strlen($token));
        $this->assertRegExp('#^[./a-zA-Z0-9]+$#', $token);
    }
    
    public function testGenerateStrongToken() {
        $obj = new org\codeangel\security\TokenUtils();
        $token = $obj->generateStrongToken(46);
        $this->assertEquals(46, strlen($token));
        $this->assertRegExp('#^[A-Za-z0-9~.`!@\#$%^&*(){}[\\]\':"\\\/.,|_+=-]+$#', $token);
    }
    
    public function testGenerateHexToken() {
        $obj = new org\codeangel\security\TokenUtils();
        $token = $obj->generateHexToken(55);
        $this->assertEquals(54, strlen($token));
        
        $token = $obj->generateHexToken(74);
        $this->assertEquals(74, strlen($token));
        $this->assertRegExp('#^[a-f0-9]+$#i', $token);
    }
    
    public function testGetRandomBytes() {
        $obj = new org\codeangel\security\TokenUtils();
        $bytes = $obj->getRandomBytes(55);
        $this->assertEquals(55, strlen($bytes));
        $this->assertRegExp('#^[\x00-\xFF]+$#', $bytes);
    }
    
    public function testForFunsies() {
        $obj = new org\codeangel\security\TokenUtils();
        //generate 1000 tokens and make sure none of them are the same:
        $array = array();
        for($i = 0; $i < 1000; $i++) {
            $array[] = $obj->generateToken(10);
        }
        $array = array_unique($array);
        $this->assertEquals(1000, count($array));
    }
    
}