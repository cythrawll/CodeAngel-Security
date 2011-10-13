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
* @package  TokenUtils
* @copyright Copyright (c) 2011 Chad Minick
* @version 1.0M1-SNAPSHOT
*/
namespace org\codeangel\security;

/**
 * 
 * use this class to generate tokens used for a variety of security purposes.
 * Uses a cryptographic random function and a configurable alphabet to maximize entropy.
 * @author Chad Minick
 *
 */
class TokenUtils {
    const ALPHA_NUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    //crypt function can use this class to generate salts, it adds a couple more chars to the ALPHA_NUM alphabet
    const CRYPT_BLOWFISH_EXTRA = "./";
    //other printable chars
    const PRINTABLE_EXTRA = "~.`!@#$%^&*(){}[]':\"\\/.,|_+=-";
    
    /**
     * 
     * Generates random bytes from a CSPRNG
     * @param int $length
     */
    public function getRandomBytes($length) {
        if(function_exists("mcrypt_create_iv")) {
            return mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
        }
        
        if(function_exists("openssl_random_pseudo_bytes")) {
            if(strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' && version_compare(PHP_VERSION, "5.4.0", "<")) {
                trigger_error("Windows users using less than version 5.4.0 might have issues with openssl_random_pseudo_bytes generating enough entropy. Please upgrade.", E_USER_WARNING);   
            }
            $strongCrypt;
            $bytes = openssl_random_pseudo_bytes($length, $strongCrypt);
            if($strongCrypt) {
                return $bytes;
            }
        }
        
        if(file_exists("/dev/urandom") && is_readable("/dev/urandom")) {
            $fh = fopen("/dev/urandom", "r+");
            $bytes = fread($fh, $length);
            fclose($fh);
            return $bytes;
        }
        
        trigger_error("No usable csprng on your system, please install openssl or mcrypt, falling back to mt_rand", E_USER_WARNING);
        $bytes = '';
        for($i = 0; $i < $length; $i++) {
            $bytes .= chr(mt_rand(0, 255));
        }
        return $bytes;
    }
    
    /**
     * 
     * creates a token from the given alphabet. defaults alpha-numeric alphabet
     * example: <code>$rand->generateTokenFromAlphabet(22, TokenUtils::ALPHANUM.TokenUtils::CRYPT_BLOWFISH_EXTRA);</code>
     * @param integer $length
     * @param string $alphabet
     */
    public function generateTokenFromAlphabet($length, $alphabet = self::ALPHA_NUM) {
        $bytes = $this->getRandomBytes($length);
        $token = "";
        foreach(str_split($bytes) as $byte) {
            $token .= $alphabet[ord($byte) % strlen($alphabet)];
        }
        return $token;
    }
    
    /**
     * 
     * Generates alpha-numeric token
     * @param int $length
     */
    public function generateToken($length) {
        return $this->generateTokenFromAlphabet($length);
    }
    
    /**
     *
     * generates salt for use with crypt() blowfish algorithm.
     */
    public function generateCryptBlowfishSalt() {
        return $this->generateTokenFromAlphabet(22, self::ALPHA_NUM.self::CRYPT_BLOWFISH_EXTRA);
    }
    
    /**
     * 
     * Token generated with even more printable characters
     * @param int $length
     */
    public function generateStrongToken($length) {
        return $this->generateTokenFromAlphabet($length, self::ALPHA_NUM.self::PRINTABLE_EXTRA);
    }
    
    /**
     *
     * For those that simply must have a hex token.
     * @param int $length must be Even number, if not even, will round down.
     */
    public function generateHexToken($length) {
        $bytes = $this->getRandomBytes(intval($length/2));
        return bin2hex($bytes);
    }
}