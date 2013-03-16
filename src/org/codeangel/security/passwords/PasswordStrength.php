<?php
/**
 * CodeAngel Security Framework
 *
 * LICENSE
 *
 * Copyright (c) 2012, Chad Minick
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
 * @copyright Copyright (c) 2012 Chad Minick
 * @version 1.0M1-SNAPSHOT
 */
namespace org\codeangel\security\passwords;

/**
 * Calculates password strength by calculating entropy
 * uses formula length * log(alphabetsize, 2);
 */
class PasswordStrength {
    const VERY_WEAK = 0;
    const WEAK = 1;
    const FAIR = 2;
    const STRONG = 3;
    const VERY_STRONG = 4;

    const START_SCORE = 100;

    protected $entropy;
    protected $score;
    protected $foundInDictionary;
    protected $dict;

    protected function init() {
        $this->entropy = 0;
        $this->score = self::START_SCORE;
        $this->foundInDictionary = false;
    }

    /**
     * @param string $password optionally pass password to calculate entropy
     * @param WordList $dict <Optional> used to see if password could be cracked with a simple dictionary lookup
     */
    public function __construct($password = null, WordList $dict = null) {
        $this->init();
        $this->dict = $dict;
        if($password != null) {
            $this->score($password);
        }
    }

    /**
     * Calculates alphabet size for entropy calculation
     * @param string $password
     * @return int
     */
    public function getAlphabet($password) {
        $alphabet = 0;
        $lower = false;
        $upper = false;
        $numbers = false;
        $symbols1 = false;
        $symbols2 = false;
        $other = '';

        foreach(str_split($password) as $chr) {
            if(!$lower && preg_match('#^[a-z]$#', $chr)) {
                $alphabet += 26;
                $lower = true;
            } else if(!$upper && preg_match('#^[A-Z]$#', $chr)) {
                $alphabet += 26;
                $upper = true;
            } else if(!$numbers && preg_match('#^[0-9]$#', $chr)) {
                $alphabet += 10;
                $numbers = true;
            } else if(!$symbols1 && preg_match('#^[!@\#$%^&*()]$#', $chr)) {
                $alphabet += 10;
                $symbols1 = true;
            } else if(!$symbols2 && preg_match('#^[~`_=+[\]{}\\|;:\'",.<>?/-]$#', $chr)) {
                $alphabet +=  22;
                $symbols2 = true;
            } else if(strpos($other, $chr) === false) {
                $alphabet += 1;
                $other .= $chr;
            }
        }
        return $alphabet;
    }

    protected function entropy($password) {
        $len = strlen($password);
        $this->entropy = $len * log($this->getAlphabet($password), 2);
    }

    /**
     * Returns the entropy of the password
     * @return float returns entropy of the password
     */
    public function getEntropy() {
        return $this->entropy;
    }

    /**
     * Returns password score
     * @return int score of password;
     */
    public function getScore() {
        return $this->score;
    }

    /**
     * Returns if the word was found in a dictionary or not.
     * @return bool whether the word was found in a dictionary or not.
     */
    public function isFoundInDictionary() {
        return $this->foundInDictionary;
    }

    protected function score($password) {
        //calculate enttropy
        $this->entropy($password);

        //is this word found in the dictionary?
        if($this->dict != null) {
            $this->foundInDictionary = $this->dict->check($password);
        }

        //is reverse of this word found in the dictionary?
        if($this->dict != null && !$this->foundInDictionary) {
            $this->foundInDictionary = $this->dict->check(strrev($password));
        }

        if(!$this->foundInDictionary) {
            if($this->entropy < 28) {
               $this->score -= 80;
            } else if($this->entropy >= 28 && $this->entropy <= 35) {
                $this->score -= 60;
            } else if($this->entropy >= 36 && $this->entropy <= 59) {
                $this->score -= 40;
            } else if($this->entropy >= 60 && $this->entropy <= 127) {
                $this->score -= 20;
            } else if($this->entropy >= 128) {
                $this->score -= 0;
            }
        } else {
            $this->score -= 80;
        }
    }

    /**
     * Calculates the general strength of the password.  matched against the constants:
     * PasswordStrength::VERY_WEAK, PasswordStrength::WEAK, PasswordStrength::FAIR
     * PasswordStrength::STRONG, PasswordStrength::VERY_STRONG
     * @return int Calculates the general strength of the password.
     */
    public function getStrength() {
        if($this->score < 21) {
            return self::VERY_WEAK;
        } else if($this->entropy >= 21 && $this->entropy <= 40) {
            return self::WEAK;
        } else if($this->entropy >= 41 && $this->entropy <= 60) {
            return self::FAIR;
        } else if($this->entropy >= 61 && $this->entropy <= 80) {
            return self::STRONG;
        } else if($this->entropy >= 81) {
            return self::VERY_STRONG;
        }
    }

    /**
     * convenience method to return word representation of password strength
     * "very weak", "weak", "fair", "strong", "very strong"
     * @return string word used to describe password strength
     */
    public function strengthWord() {
        $str = $this->getStrength();

        if($str === self::VERY_WEAK) {
            return "very weak";
        }

        if($str === self::WEAK) {
            return "weak";
        }

        if($str === self::FAIR) {
            return 'fair';
        }

        if($str === self::STRONG) {
            return 'strong';
        }

        if($str === self::VERY_STRONG) {
            return 'very strong';
        }
    }

    /**
     * sets the password
     * @param string $password
     */
    public function setPassword($password) {
        $this->init();
        $this->score($password);
    }
}