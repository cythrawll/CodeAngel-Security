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
* @category CodeAngel Security
* @package  Passwords
* @copyright Copyright (c) 2011 Chad Minick
* @version 1.0M1-SNAPSHOT
*/
namespace org\codeangel\security\passwords;

abstract class CryptPasswordGenerator implements PasswordGenerator {
    protected $minRounds;
    protected $maxRounds;
    protected $format;
    
    abstract protected function getSalt();
    
    protected function getFormat() {
        $salt = $this->getSalt();
        $rounds = mt_rand($this->minRounds, $this->maxRounds);
        $rounds = sprintf("%02d", $rounds);
        return sprintf($this->format, $rounds, $salt);
    } 

    /**
     * hashes a password
     * @param $password string password to hash
     * @return string hashed password
     */
    public function genPassword($password) {
        return crypt($password, $this->getFormat());
    }

    /**
     * Checks entered password matches the hash
     * @param $password string password that the user supplied
     * @param $expected string hash from storage (eg. from your database)
     * @return bool whether or not the password matched or not
     */
    public function checkPassword($password, $expected) {
        return PasswordUtils::compare(crypt($password, $expected), $expected);
    }

    /**
     * overrides default cost of the hash, will randomize between min and max.
     * @param $min
     * @param $max
     */
    public function setCost($min, $max) {
        $this->minRounds = $min;
        $this->maxRounds = $max;
    }
}