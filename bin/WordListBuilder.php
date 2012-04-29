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

/**
 * CLI file for generating a sqlite file from a wordlist
 */
$usage = "php[.exe] WordListBuilder.php [input word list] [output .sq3 file]" . PHP_EOL;

if (!extension_loaded("pdo_sqlite")) {
    echo "this requires the PDO SQLite extension, please install!" . PHP_EOL;
    exit;
}

if ($argc != 3): ?>

This is a command line PHP script with two options.

Usage:
<?php echo $argv[0]; ?> <input> <output>

    <input> The wordlist file you'd like to process,
        should all be in lowercase and separated by newline
        can be compressed (if php has the zip extension).
        If compressed, filename should end with .gz.
        example wordlist for english:
        http://sourceforge.net/projects/cracklib/files/cracklib-words/2008-05-07/cracklib-words-20080507.gz/download

    <output> The sqlite file that should be created.
        should end in .sq3 (but really whatever you want)

<?php
else:
    $input = $argv[1];
    $output = $argv[2];
    $db = new PDO("sqlite:$output");
    $db->exec("CREATE TABLE IF NOT EXISTS words ( word VARCHAR(5) PRIMARY KEY )");
    if (endswith($input, ".gz") && strpos($input, "zlib://") !== 0) {
        $input = "zlib://" . $input;
    }
    if (strpos($input, "zlib://") === 0 && !extension_loaded("zlib")) {
        echo "Zlib support needs to be enabled to read gzipped files" . PHP_EOL;
    }
    if (strpos($input, "zlib://") === 0) {
        $fp = gzopen($input, 'r');
    } else {
        $fp = fopen($input, 'r');
    }

    if ($fp) {
        $stmt = $db->prepare("INSERT INTO words VALUES(:word)");
        $count = 0;
        while (($word = fgets($fp)) !== false) {
            $word = trim($word);
            $stmt->bindValue(':word', $word, PDO::PARAM_STR);
            $stmt->execute();
            $count = $count + $stmt->rowCount();
            if ($count % 300 === 0) {
                echo '.';
            }
        }
        if (!feof($fp)) {
            echo "Error: unexpected fgets() fail" . PHP_EOL;
        }
        fclose($fp);
        echo PHP_EOL . $count . " words inserted" . PHP_EOL;
    } else {
        echo "Error couldn't open file $input" . PHP_EOL;
    }


endif;

function endswith($string, $test) {
    $strlen = strlen($string);
    $testlen = strlen($test);
    if ($testlen > $strlen) return false;
    return substr_compare($string, $test, -$testlen) === 0;
}