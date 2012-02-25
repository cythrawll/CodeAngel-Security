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
 * Koremetake generator, see http://shorl.com/koremutake for details
 */
class KoremutakePassword {
    private $phonemes = array('BA', 'BE', 'BI', 'BO', 'BU', 'BY', 'DA', 'DE', 'DI', 'DO', 'DU', 'DY', 'FA',
        'FE', 'FI', 'FO', 'FU', 'FY', 'GA', 'GE', 'GI', 'GO', 'GU', 'GY', 'HA', 'HE', 'HI', 'HO', 'HU', 'HY',
        'JA', 'JE', 'JI', 'JO', 'JU', 'JY', 'KA', 'KE', 'KI', 'KO', 'KU', 'KY', 'LA', 'LE', 'LI', 'LO', 'LU',
        'LY', 'MA', 'ME', 'MI', 'MO', 'MU', 'MY', 'NA', 'NE', 'NI', 'NO', 'NU', 'NY', 'PA', 'PE', 'PI', 'PO',
        'PU', 'PY', 'RA', 'RE', 'RI', 'RO', 'RU', 'RY', 'SA', 'SE', 'SI', 'SO', 'SU', 'SY', 'TA', 'TE', 'TI',
        'TO', 'TU', 'TY', 'VA', 'VE', 'VI', 'VO', 'VU', 'VY', 'BRA', 'BRE', 'BRI', 'BRO', 'BRU', 'BRY', 'DRA',
        'DRE', 'DRI', 'DRO', 'DRU', 'DRY', 'FRA', 'FRE', 'FRI', 'FRO', 'FRU', 'FRY', 'GRA', 'GRE', 'GRI',
        'GRO', 'GRU', 'GRY', 'PRA', 'PRE', 'PRI', 'PRO', 'PRU', 'PRY', 'STA', 'STE', 'STI', 'STO', 'STU',
        'STY', 'TRA', 'TRE'
    );

    private function numbersToKoremutake(Array $numbers) {
        $string = "";
        foreach($numbers as $num) {
            if(!is_int($num)) {
                throw new \Exception("array must contain integers");
            }
            if($num < 0 || $num > 127 ) {
                throw new \Exception("numbers must be between 0 and 127");
            }

            $string .= $this->phonemes[$num];
        }
        return $string;
    }

    private function koremutakeToNumbers($string) {
        $numbers = array();
        $phoneme = "";
        $chars = str_split($string);
        foreach($chars as $char) {
            $phoneme .= $char;
            if(!preg_match('#^[aeiouy]$#i', $char)) {
                continue;
            }
            $number = array_search($phoneme, $this->phonemes);
            if($number === false) {
                throw new \Exception("$phoneme is not a valid phoneme");
            }
            array_push($numbers, $number);
            $phoneme = "";
        }
       return $numbers;
    }

    /**
     * Returns a koremetake representation of an integer
     * @param  int $int
     * @return string koremetake representation of integer
     * @throws \Exception throws if $int is negative
     */
    public function integerToKoremutake($int) {
        if($int < 0) {
            throw new \Exception("Negative Integers not acceptable");
        }

        $numbers = array();
        if($int == 0) {
            $numbers = array(0);
        }

        while($int != 0) {
            array_push($numbers, $int % 128);
            $int = (int)($int/128);
        }
        return strtolower($this->numbersToKoremutake(array_reverse($numbers)));
    }

    /**
     * Returns integer from a koremetake string
     * @param string $string koremetake string
     * @return int integer representation of string
     * @throws \Exception throws if string is not a valid koremetake string
     */
    public function koremutakeToInteger($string) {
        $numbers = $this->koremutakeToNumbers(strtoupper($string));
        $int = 0;
        foreach($numbers as $num) {
            $int = ($int * 128) + $num;
        }
        return $int;
    }
}
