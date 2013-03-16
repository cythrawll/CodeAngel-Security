<?php
/**
 * CodeAngel Security Framework
 *
 * LICENSE
 *
 * Copyright (c) 2011, 2012 Chad Minick
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
 *
 * This code was a port of the pronounceable password generator in APG -- by Adel I. Mirzazhanov
 */
namespace org\codeangel\security\passwords;

class PasswordUtils {

    /**
     * Takes a string and randomly capitilizes letters
     * @static
     * @param string $string
     * @return string
     */
    public static function randomCaptilize($string) {
        $newString = '';
        foreach(str_split($string) as $chr) {
            if(mt_rand(0,1) === 1) {
                $newString .= strtoupper($chr);
            } else {
                $newString .= $chr;
            }
        }
        return $newString;
    }

    /**
     * Takes a string and capitilizes every other word
     * @static
     * @param string $string
     * @param bool $even Whether to start capitilizing even or odd characters.
     * @return string
     */
    public static function capitilizeAlternating($string, $even = true) {
        $newString = '';
        foreach(str_split($string) as $pos => $chr) {
            if($pos % 2 == 0 && !$even) {
                $newString .= strtoupper($chr);
            } elseif($pos % 2 != 0 && $even) {
                $newString .= strtoupper($chr);
            } else {
                $newString .= $chr;
            }
        }
        return $newString;
    }

    /**
     * Takes a string and replaces certain letters with numbers
     * @static
     * @param string $string
     * @param bool $ignoreCase Some letter replacement depends on case, set to true to make it case insensitive
     * @return string
     */
    public static function numerize($string, $ignoreCase = false) {
        $arr = array('A' => '4', 'l' => '1', 'E' => '3', 'B' => '8', 'g' => '9', 'O' => '0', 'o' => '0', 's' => '5', 'S' => '5', 'T' => '7');
        return self::replace($string, $arr, $ignoreCase);
    }

    /**
     * Takes a string and replaces certain letters with special chars.
     * @static
     * @param string $string
     * @param bool $ignoreCase Some letter replacement depends on case, set to true to make it case insensitive
     * @return string
     */
    public static function symbolize($string, $ignoreCase = false) {
        $arr = array('a' => '@', 'S' => '$', 's' => '$', 'H' => '#', 'i' => '!', 'x' => '%', 'X' => '%');
        return self::replace($string, $arr, $ignoreCase);
    }

    /**
     * Takes a string and replaces certain letters with either numbers or special chars.
     * @static
     * @param string $string
     * @param bool $ignoreCase Some letter replacement depends on case, set to true to make it case insensitive
     * @return string
     */
    public static function numsymolize($string ,$ignoreCase = false) {
        return self::symbolize(self::numerize($string, $ignoreCase), $ignoreCase);
    }

    protected static function replace($string, $array, $ignoreCase = false) {
        $keys = array_keys($array);
        $vals = array_values($array);

        if($ignoreCase) {
            $newString = str_ireplace($keys, $vals, $string);
        } else {
            $newString = str_replace($keys, $vals, $string);
        }
        return $newString;
    }

    public static function compare($str1, $str2) {
        if (strlen($str1) !== strlen($str2)) {
            return false;
        }
        $result = 0;
        for ($i = 0; $i < strlen($str1); $i++) {
            $result |= ord($str1[$i]) ^ ord($str2[$i]);
        }
        return $result == 0;
    }
}