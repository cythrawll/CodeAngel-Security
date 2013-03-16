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
//TODO: Needs lots of clean up since this is pretty much a direct port.
namespace org\codeangel\security\passwords;

class PronPassword {

    const NOT_BEGIN_SYLLABLE = 010;
    const NO_FINAL_SPLIT = 04;
    const VOWEL = 02;
    const ALTERNATE_VOWEL = 01;
    const NO_SPECIAL_RULE = 0;

    const BEGIN = 0200;
    const NOT_BEGIN = 0100;
    const BRAKE = 040;
    const PREFIX = 020;
    const ILLEGAL_PAIR = 010;
    const SUFFIX = 04;
    const END = 02;
    const NOT_END = 01;
    const ANY_COMBINATION = 0;

    private $rules;
    private $digram;
    protected $maxRetries;


    public function __construct() {
        $this->rules = array(
            array("a", PronPassword::VOWEL),
            array("b", PronPassword::NO_SPECIAL_RULE),
            array("c", PronPassword::NO_SPECIAL_RULE),
            array("d", PronPassword::NO_SPECIAL_RULE),
            array("e", PronPassword::NO_FINAL_SPLIT | PronPassword::VOWEL),
            array("f", PronPassword::NO_SPECIAL_RULE),
            array("g", PronPassword::NO_SPECIAL_RULE),
            array("h", PronPassword::NO_SPECIAL_RULE),
            array("i", PronPassword::VOWEL),
            array("j", PronPassword::NO_SPECIAL_RULE),
            array("k", PronPassword::NO_SPECIAL_RULE),
            array("l", PronPassword::NO_SPECIAL_RULE),
            array("m", PronPassword::NO_SPECIAL_RULE),
            array("n", PronPassword::NO_SPECIAL_RULE),
            array("o", PronPassword::VOWEL),
            array("p", PronPassword::NO_SPECIAL_RULE),
            array("r", PronPassword::NO_SPECIAL_RULE),
            array("s", PronPassword::NO_SPECIAL_RULE),
            array("t", PronPassword::NO_SPECIAL_RULE),
            array("u", PronPassword::VOWEL),
            array("v", PronPassword::NO_SPECIAL_RULE),
            array("w", PronPassword::NO_SPECIAL_RULE),
            array("x", PronPassword::NOT_BEGIN_SYLLABLE),
            array("y", PronPassword::ALTERNATE_VOWEL | PronPassword::VOWEL),
            array("z", PronPassword::NO_SPECIAL_RULE),
            array("ch", PronPassword::NO_SPECIAL_RULE),
            array("gh", PronPassword::NO_SPECIAL_RULE),
            array("ph", PronPassword::NO_SPECIAL_RULE),
            array("rh", PronPassword::NO_SPECIAL_RULE),
            array("sh", PronPassword::NO_SPECIAL_RULE),
            array("th", PronPassword::NO_SPECIAL_RULE),
            array("wh", PronPassword::NO_SPECIAL_RULE),
            array("qu", PronPassword::NO_SPECIAL_RULE),
            array("ck", PronPassword::NOT_BEGIN_SYLLABLE)
        );

        $this->digram =
            array(
                array(/* aa */ PronPassword::ILLEGAL_PAIR,
                    /* ab */ PronPassword::ANY_COMBINATION,
                    /* ac */ PronPassword::ANY_COMBINATION,
                    /* ad */ PronPassword::ANY_COMBINATION,
                    /* ae */ PronPassword::ILLEGAL_PAIR,
                    /* af */ PronPassword::ANY_COMBINATION,
                    /* ag */ PronPassword::ANY_COMBINATION,
                    /* ah */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ai */ PronPassword::ANY_COMBINATION,
                    /* aj */ PronPassword::ANY_COMBINATION,
                    /* ak */ PronPassword::ANY_COMBINATION,
                    /* al */ PronPassword::ANY_COMBINATION,
                    /* am */ PronPassword::ANY_COMBINATION,
                    /* an */ PronPassword::ANY_COMBINATION,
                    /* ao */ PronPassword::ILLEGAL_PAIR,
                    /* ap */ PronPassword::ANY_COMBINATION,
                    /* ar */ PronPassword::ANY_COMBINATION,
                    /* as */ PronPassword::ANY_COMBINATION,
                    /* at */ PronPassword::ANY_COMBINATION,
                    /* au */ PronPassword::ANY_COMBINATION,
                    /* av */ PronPassword::ANY_COMBINATION,
                    /* aw */ PronPassword::ANY_COMBINATION,
                    /* ax */ PronPassword::ANY_COMBINATION,
                    /* ay */ PronPassword::ANY_COMBINATION,
                    /* az */ PronPassword::ANY_COMBINATION,
                    /* ach */ PronPassword::ANY_COMBINATION,
                    /* agh */ PronPassword::ILLEGAL_PAIR,
                    /* aph */ PronPassword::ANY_COMBINATION,
                    /* arh */ PronPassword::ILLEGAL_PAIR,
                    /* ash */ PronPassword::ANY_COMBINATION,
                    /* ath */ PronPassword::ANY_COMBINATION,
                    /* awh */ PronPassword::ILLEGAL_PAIR,
                    /* aqu */ PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ack */ PronPassword::ANY_COMBINATION),
                array(/* ba */ PronPassword::ANY_COMBINATION,
                    /* bb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* be */ PronPassword::ANY_COMBINATION,
                    /* bf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bi */ PronPassword::ANY_COMBINATION,
                    /* bj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bl */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* bm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bo */ PronPassword::ANY_COMBINATION,
                    /* bp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* br */ PronPassword::BEGIN | PronPassword::END,
                    /* bs */ PronPassword::NOT_BEGIN,
                    /* bt */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bu */ PronPassword::ANY_COMBINATION,
                    /* bv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bx */ PronPassword::ILLEGAL_PAIR,
                    /* by */ PronPassword::ANY_COMBINATION,
                    /* bz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bgh */ PronPassword::ILLEGAL_PAIR,
                    /* bph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* brh */ PronPassword::ILLEGAL_PAIR,
                    /* bsh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bwh */ PronPassword::ILLEGAL_PAIR,
                    /* bqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* bck */ PronPassword::ILLEGAL_PAIR ),
                array(/* ca */ PronPassword::ANY_COMBINATION,
                    /* cb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ce */ PronPassword::ANY_COMBINATION,
                    /* cf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ci */ PronPassword::ANY_COMBINATION,
                    /* cj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ck */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cl */ PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* cm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* co */ PronPassword::ANY_COMBINATION,
                    /* cp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cr */ PronPassword::NOT_END,
                    /* cs */ PronPassword::NOT_BEGIN | PronPassword::END,
                    /* ct */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* cu */ PronPassword::ANY_COMBINATION,
                    /* cv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cx */ PronPassword::ILLEGAL_PAIR,
                    /* cy */ PronPassword::ANY_COMBINATION,
                    /* cz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cch */ PronPassword::ILLEGAL_PAIR,
                    /* cgh */ PronPassword::ILLEGAL_PAIR,
                    /* cph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* crh */ PronPassword::ILLEGAL_PAIR,
                    /* csh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cwh */ PronPassword::ILLEGAL_PAIR,
                    /* cqu */ PronPassword::NOT_BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* cck */ PronPassword::ILLEGAL_PAIR),
                array(/* da */ PronPassword::ANY_COMBINATION,
                    /* db */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dd */ PronPassword::NOT_BEGIN,
                    /* de */ PronPassword::ANY_COMBINATION,
                    /* df */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* di */ PronPassword::ANY_COMBINATION,
                    /* dj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dl */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* do */ PronPassword::ANY_COMBINATION,
                    /* dp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dr */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* ds */ PronPassword::NOT_BEGIN | PronPassword::END,
                    /* dt */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* du */ PronPassword::ANY_COMBINATION,
                    /* dv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dx */ PronPassword::ILLEGAL_PAIR,
                    /* dy */ PronPassword::ANY_COMBINATION,
                    /* dz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* drh */ PronPassword::ILLEGAL_PAIR,
                    /* dsh */ PronPassword::NOT_BEGIN | PronPassword::NOT_END,
                    /* dth */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* dwh */ PronPassword::ILLEGAL_PAIR,
                    /* dqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* dck */ PronPassword::ILLEGAL_PAIR ),
                array(/* ea */ PronPassword::ANY_COMBINATION,
                    /* eb */ PronPassword::ANY_COMBINATION,
                    /* ec */ PronPassword::ANY_COMBINATION,
                    /* ed */ PronPassword::ANY_COMBINATION,
                    /* ee */ PronPassword::ANY_COMBINATION,
                    /* ef */ PronPassword::ANY_COMBINATION,
                    /* eg */ PronPassword::ANY_COMBINATION,
                    /* eh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ei */ PronPassword::NOT_END,
                    /* ej */ PronPassword::ANY_COMBINATION,
                    /* ek */ PronPassword::ANY_COMBINATION,
                    /* el */ PronPassword::ANY_COMBINATION,
                    /* em */ PronPassword::ANY_COMBINATION,
                    /* en */ PronPassword::ANY_COMBINATION,
                    /* eo */ PronPassword::BRAKE,
                    /* ep */ PronPassword::ANY_COMBINATION,
                    /* er */ PronPassword::ANY_COMBINATION,
                    /* es */ PronPassword::ANY_COMBINATION,
                    /* et */ PronPassword::ANY_COMBINATION,
                    /* eu */ PronPassword::ANY_COMBINATION,
                    /* ev */ PronPassword::ANY_COMBINATION,
                    /* ew */ PronPassword::ANY_COMBINATION,
                    /* ex */ PronPassword::ANY_COMBINATION,
                    /* ey */ PronPassword::ANY_COMBINATION,
                    /* ez */ PronPassword::ANY_COMBINATION,
                    /* ech */ PronPassword::ANY_COMBINATION,
                    /* egh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* eph */ PronPassword::ANY_COMBINATION,
                    /* erh */ PronPassword::ILLEGAL_PAIR,
                    /* esh */ PronPassword::ANY_COMBINATION,
                    /* eth */ PronPassword::ANY_COMBINATION,
                    /* ewh */ PronPassword::ILLEGAL_PAIR,
                    /* equ */ PronPassword::BRAKE | PronPassword::NOT_END,
                    /* eck */ PronPassword::ANY_COMBINATION ),
                array(/* fa */ PronPassword::ANY_COMBINATION,
                    /* fb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fe */ PronPassword::ANY_COMBINATION,
                    /* ff */ PronPassword::NOT_BEGIN,
                    /* fg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fi */ PronPassword::ANY_COMBINATION,
                    /* fj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fl */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* fm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fo */ PronPassword::ANY_COMBINATION,
                    /* fp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fr */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* fs */ PronPassword::NOT_BEGIN,
                    /* ft */ PronPassword::NOT_BEGIN,
                    /* fu */ PronPassword::ANY_COMBINATION,
                    /* fv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fx */ PronPassword::ILLEGAL_PAIR,
                    /* fy */ PronPassword::NOT_BEGIN,
                    /* fz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* frh */ PronPassword::ILLEGAL_PAIR,
                    /* fsh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fwh */ PronPassword::ILLEGAL_PAIR,
                    /* fqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* fck */ PronPassword::ILLEGAL_PAIR ),
                array(/* ga */ PronPassword::ANY_COMBINATION,
                    /* gb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* gc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* gd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ge */ PronPassword::ANY_COMBINATION,
                    /* gf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* gg */ PronPassword::NOT_BEGIN,
                    /* gh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* gi */ PronPassword::ANY_COMBINATION,
                    /* gj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* gk */ PronPassword::ILLEGAL_PAIR,
                    /* gl */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* gm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* gn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* go */ PronPassword::ANY_COMBINATION,
                    /* gp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* gr */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* gs */ PronPassword::NOT_BEGIN | PronPassword::END,
                    /* gt */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* gu */ PronPassword::ANY_COMBINATION,
                    /* gv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* gw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* gx */ PronPassword::ILLEGAL_PAIR,
                    /* gy */ PronPassword::NOT_BEGIN,
                    /* gz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* gch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ggh */ PronPassword::ILLEGAL_PAIR,
                    /* gph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* grh */ PronPassword::ILLEGAL_PAIR,
                    /* gsh */ PronPassword::NOT_BEGIN,
                    /* gth */ PronPassword::NOT_BEGIN,
                    /* gwh */ PronPassword::ILLEGAL_PAIR,
                    /* gqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* gck */ PronPassword::ILLEGAL_PAIR ),
                array(/* ha */ PronPassword::ANY_COMBINATION,
                    /* hb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* he */ PronPassword::ANY_COMBINATION,
                    /* hf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hh */ PronPassword::ILLEGAL_PAIR,
                    /* hi */ PronPassword::ANY_COMBINATION,
                    /* hj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hl */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ho */ PronPassword::ANY_COMBINATION,
                    /* hp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hr */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hs */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ht */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hu */ PronPassword::ANY_COMBINATION,
                    /* hv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hx */ PronPassword::ILLEGAL_PAIR,
                    /* hy */ PronPassword::ANY_COMBINATION,
                    /* hz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hrh */ PronPassword::ILLEGAL_PAIR,
                    /* hsh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hwh */ PronPassword::ILLEGAL_PAIR,
                    /* hqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* hck */ PronPassword::ILLEGAL_PAIR ),
                array(/* ia */ PronPassword::ANY_COMBINATION,
                    /* ib */ PronPassword::ANY_COMBINATION,
                    /* ic */ PronPassword::ANY_COMBINATION,
                    /* id */ PronPassword::ANY_COMBINATION,
                    /* ie */ PronPassword::NOT_BEGIN,
                    /* if */ PronPassword::ANY_COMBINATION,
                    /* ig */ PronPassword::ANY_COMBINATION,
                    /* ih */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ii */ PronPassword::ILLEGAL_PAIR,
                    /* ij */ PronPassword::ANY_COMBINATION,
                    /* ik */ PronPassword::ANY_COMBINATION,
                    /* il */ PronPassword::ANY_COMBINATION,
                    /* im */ PronPassword::ANY_COMBINATION,
                    /* in */ PronPassword::ANY_COMBINATION,
                    /* io */ PronPassword::BRAKE,
                    /* ip */ PronPassword::ANY_COMBINATION,
                    /* ir */ PronPassword::ANY_COMBINATION,
                    /* is */ PronPassword::ANY_COMBINATION,
                    /* it */ PronPassword::ANY_COMBINATION,
                    /* iu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* iv */ PronPassword::ANY_COMBINATION,
                    /* iw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ix */ PronPassword::ANY_COMBINATION,
                    /* iy */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* iz */ PronPassword::ANY_COMBINATION,
                    /* ich */ PronPassword::ANY_COMBINATION,
                    /* igh */ PronPassword::NOT_BEGIN,
                    /* iph */ PronPassword::ANY_COMBINATION,
                    /* irh */ PronPassword::ILLEGAL_PAIR,
                    /* ish */ PronPassword::ANY_COMBINATION,
                    /* ith */ PronPassword::ANY_COMBINATION,
                    /* iwh */ PronPassword::ILLEGAL_PAIR,
                    /* iqu */ PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ick */ PronPassword::ANY_COMBINATION ),
                array(/* ja */ PronPassword::ANY_COMBINATION,
                    /* jb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* je */ PronPassword::ANY_COMBINATION,
                    /* jf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jg */ PronPassword::ILLEGAL_PAIR,
                    /* jh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ji */ PronPassword::ANY_COMBINATION,
                    /* jj */ PronPassword::ILLEGAL_PAIR,
                    /* jk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jl */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jo */ PronPassword::ANY_COMBINATION,
                    /* jp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jr */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* js */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jt */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ju */ PronPassword::ANY_COMBINATION,
                    /* jv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jx */ PronPassword::ILLEGAL_PAIR,
                    /* jy */ PronPassword::NOT_BEGIN,
                    /* jz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jrh */ PronPassword::ILLEGAL_PAIR,
                    /* jsh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jwh */ PronPassword::ILLEGAL_PAIR,
                    /* jqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* jck */ PronPassword::ILLEGAL_PAIR ),
                array(/* ka */ PronPassword::ANY_COMBINATION,
                    /* kb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ke */ PronPassword::ANY_COMBINATION,
                    /* kf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ki */ PronPassword::ANY_COMBINATION,
                    /* kj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kl */ PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* km */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kn */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* ko */ PronPassword::ANY_COMBINATION,
                    /* kp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kr */ PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* ks */ PronPassword::NOT_BEGIN | PronPassword::END,
                    /* kt */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ku */ PronPassword::ANY_COMBINATION,
                    /* kv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kx */ PronPassword::ILLEGAL_PAIR,
                    /* ky */ PronPassword::NOT_BEGIN,
                    /* kz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kph */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* krh */ PronPassword::ILLEGAL_PAIR,
                    /* ksh */ PronPassword::NOT_BEGIN,
                    /* kth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kwh */ PronPassword::ILLEGAL_PAIR,
                    /* kqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* kck */ PronPassword::ILLEGAL_PAIR ),
                array(/* la */ PronPassword::ANY_COMBINATION,
                    /* lb */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* lc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ld */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* le */ PronPassword::ANY_COMBINATION,
                    /* lf */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* lg */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* lh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* li */ PronPassword::ANY_COMBINATION,
                    /* lj */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* lk */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* ll */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* lm */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* ln */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* lo */ PronPassword::ANY_COMBINATION,
                    /* lp */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* lr */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ls */ PronPassword::NOT_BEGIN,
                    /* lt */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* lu */ PronPassword::ANY_COMBINATION,
                    /* lv */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* lw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* lx */ PronPassword::ILLEGAL_PAIR,
                    /* ly */ PronPassword::ANY_COMBINATION,
                    /* lz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* lch */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* lgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* lph */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* lrh */ PronPassword::ILLEGAL_PAIR,
                    /* lsh */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* lth */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* lwh */ PronPassword::ILLEGAL_PAIR,
                    /* lqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* lck */ PronPassword::ILLEGAL_PAIR ),
                array(/* ma */ PronPassword::ANY_COMBINATION,
                    /* mb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* mc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* md */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* me */ PronPassword::ANY_COMBINATION,
                    /* mf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* mg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* mh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* mi */ PronPassword::ANY_COMBINATION,
                    /* mj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* mk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ml */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* mm */ PronPassword::NOT_BEGIN,
                    /* mn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* mo */ PronPassword::ANY_COMBINATION,
                    /* mp */ PronPassword::NOT_BEGIN,
                    /* mr */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ms */ PronPassword::NOT_BEGIN,
                    /* mt */ PronPassword::NOT_BEGIN,
                    /* mu */ PronPassword::ANY_COMBINATION,
                    /* mv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* mw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* mx */ PronPassword::ILLEGAL_PAIR,
                    /* my */ PronPassword::ANY_COMBINATION,
                    /* mz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* mch */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* mgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* mph */ PronPassword::NOT_BEGIN,
                    /* mrh */ PronPassword::ILLEGAL_PAIR,
                    /* msh */ PronPassword::NOT_BEGIN,
                    /* mth */ PronPassword::NOT_BEGIN,
                    /* mwh */ PronPassword::ILLEGAL_PAIR,
                    /* mqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* mck */ PronPassword::ILLEGAL_PAIR ),
                array(/* na */ PronPassword::ANY_COMBINATION,
                    /* nb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* nc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* nd */ PronPassword::NOT_BEGIN,
                    /* ne */ PronPassword::ANY_COMBINATION,
                    /* nf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ng */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* nh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ni */ PronPassword::ANY_COMBINATION,
                    /* nj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* nk */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* nl */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* nm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* nn */ PronPassword::NOT_BEGIN,
                    /* no */ PronPassword::ANY_COMBINATION,
                    /* np */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* nr */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ns */ PronPassword::NOT_BEGIN,
                    /* nt */ PronPassword::NOT_BEGIN,
                    /* nu */ PronPassword::ANY_COMBINATION,
                    /* nv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* nw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* nx */ PronPassword::ILLEGAL_PAIR,
                    /* ny */ PronPassword::NOT_BEGIN,
                    /* nz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* nch */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* ngh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* nph */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* nrh */ PronPassword::ILLEGAL_PAIR,
                    /* nsh */ PronPassword::NOT_BEGIN,
                    /* nth */ PronPassword::NOT_BEGIN,
                    /* nwh */ PronPassword::ILLEGAL_PAIR,
                    /* nqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* nck */ PronPassword::NOT_BEGIN | PronPassword::PREFIX ),
                array(/* oa */ PronPassword::ANY_COMBINATION,
                    /* ob */ PronPassword::ANY_COMBINATION,
                    /* oc */ PronPassword::ANY_COMBINATION,
                    /* od */ PronPassword::ANY_COMBINATION,
                    /* oe */ PronPassword::ILLEGAL_PAIR,
                    /* of */ PronPassword::ANY_COMBINATION,
                    /* og */ PronPassword::ANY_COMBINATION,
                    /* oh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* oi */ PronPassword::ANY_COMBINATION,
                    /* oj */ PronPassword::ANY_COMBINATION,
                    /* ok */ PronPassword::ANY_COMBINATION,
                    /* ol */ PronPassword::ANY_COMBINATION,
                    /* om */ PronPassword::ANY_COMBINATION,
                    /* on */ PronPassword::ANY_COMBINATION,
                    /* oo */ PronPassword::ANY_COMBINATION,
                    /* op */ PronPassword::ANY_COMBINATION,
                    /* or */ PronPassword::ANY_COMBINATION,
                    /* os */ PronPassword::ANY_COMBINATION,
                    /* ot */ PronPassword::ANY_COMBINATION,
                    /* ou */ PronPassword::ANY_COMBINATION,
                    /* ov */ PronPassword::ANY_COMBINATION,
                    /* ow */ PronPassword::ANY_COMBINATION,
                    /* ox */ PronPassword::ANY_COMBINATION,
                    /* oy */ PronPassword::ANY_COMBINATION,
                    /* oz */ PronPassword::ANY_COMBINATION,
                    /* och */ PronPassword::ANY_COMBINATION,
                    /* ogh */ PronPassword::NOT_BEGIN,
                    /* oph */ PronPassword::ANY_COMBINATION,
                    /* orh */ PronPassword::ILLEGAL_PAIR,
                    /* osh */ PronPassword::ANY_COMBINATION,
                    /* oth */ PronPassword::ANY_COMBINATION,
                    /* owh */ PronPassword::ILLEGAL_PAIR,
                    /* oqu */ PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ock */ PronPassword::ANY_COMBINATION ),
                array(/* pa */ PronPassword::ANY_COMBINATION,
                    /* pb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pe */ PronPassword::ANY_COMBINATION,
                    /* pf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pi */ PronPassword::ANY_COMBINATION,
                    /* pj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pl */ PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* pm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* po */ PronPassword::ANY_COMBINATION,
                    /* pp */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* pr */ PronPassword::NOT_END,
                    /* ps */ PronPassword::NOT_BEGIN | PronPassword::END,
                    /* pt */ PronPassword::NOT_BEGIN | PronPassword::END,
                    /* pu */ PronPassword::NOT_BEGIN | PronPassword::END,
                    /* pv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* px */ PronPassword::ILLEGAL_PAIR,
                    /* py */ PronPassword::ANY_COMBINATION,
                    /* pz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* prh */ PronPassword::ILLEGAL_PAIR,
                    /* psh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pwh */ PronPassword::ILLEGAL_PAIR,
                    /* pqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pck */ PronPassword::ILLEGAL_PAIR ),
                array(/* ra */ PronPassword::ANY_COMBINATION,
                    /* rb */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rc */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rd */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* re */ PronPassword::ANY_COMBINATION,
                    /* rf */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rg */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ri */ PronPassword::ANY_COMBINATION,
                    /* rj */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rk */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rl */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rm */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rn */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* ro */ PronPassword::ANY_COMBINATION,
                    /* rp */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rr */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rs */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rt */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* ru */ PronPassword::ANY_COMBINATION,
                    /* rv */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* rx */ PronPassword::ILLEGAL_PAIR,
                    /* ry */ PronPassword::ANY_COMBINATION,
                    /* rz */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rch */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* rph */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rrh */ PronPassword::ILLEGAL_PAIR,
                    /* rsh */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rth */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* rwh */ PronPassword::ILLEGAL_PAIR,
                    /* rqu */ PronPassword::NOT_BEGIN | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* rck */ PronPassword::NOT_BEGIN | PronPassword::PREFIX ),
                array(/* sa */ PronPassword::ANY_COMBINATION,
                    /* sb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* sc */ PronPassword::NOT_END,
                    /* sd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* se */ PronPassword::ANY_COMBINATION,
                    /* sf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* sg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* sh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* si */ PronPassword::ANY_COMBINATION,
                    /* sj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* sk */ PronPassword::ANY_COMBINATION,
                    /* sl */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* sm */ PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* sn */ PronPassword::PREFIX | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* so */ PronPassword::ANY_COMBINATION,
                    /* sp */ PronPassword::ANY_COMBINATION,
                    /* sr */ PronPassword::NOT_BEGIN | PronPassword::NOT_END,
                    /* ss */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* st */ PronPassword::ANY_COMBINATION,
                    /* su */ PronPassword::ANY_COMBINATION,
                    /* sv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* sw */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* sx */ PronPassword::ILLEGAL_PAIR,
                    /* sy */ PronPassword::ANY_COMBINATION,
                    /* sz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* sch */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* sgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* sph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* srh */ PronPassword::ILLEGAL_PAIR,
                    /* ssh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* sth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* swh */ PronPassword::ILLEGAL_PAIR,
                    /* squ */ PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* sck */ PronPassword::NOT_BEGIN ),
                array(/* ta */ PronPassword::ANY_COMBINATION,
                    /* tb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* tc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* td */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* te */ PronPassword::ANY_COMBINATION,
                    /* tf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* tg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* th */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ti */ PronPassword::ANY_COMBINATION,
                    /* tj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* tk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* tl */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* tm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* tn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* to */ PronPassword::ANY_COMBINATION,
                    /* tp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* tr */ PronPassword::NOT_END,
                    /* ts */ PronPassword::NOT_BEGIN | PronPassword::END,
                    /* tt */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* tu */ PronPassword::ANY_COMBINATION,
                    /* tv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* tw */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* tx */ PronPassword::ILLEGAL_PAIR,
                    /* ty */ PronPassword::ANY_COMBINATION,
                    /* tz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* tch */ PronPassword::NOT_BEGIN,
                    /* tgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* tph */ PronPassword::NOT_BEGIN | PronPassword::END,
                    /* trh */ PronPassword::ILLEGAL_PAIR,
                    /* tsh */ PronPassword::NOT_BEGIN | PronPassword::END,
                    /* tth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* twh */ PronPassword::ILLEGAL_PAIR,
                    /* tqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* tck */ PronPassword::ILLEGAL_PAIR ),
                array(/* ua */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ub */ PronPassword::ANY_COMBINATION,
                    /* uc */ PronPassword::ANY_COMBINATION,
                    /* ud */ PronPassword::ANY_COMBINATION,
                    /* ue */ PronPassword::NOT_BEGIN,
                    /* uf */ PronPassword::ANY_COMBINATION,
                    /* ug */ PronPassword::ANY_COMBINATION,
                    /* uh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ui */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* uj */ PronPassword::ANY_COMBINATION,
                    /* uk */ PronPassword::ANY_COMBINATION,
                    /* ul */ PronPassword::ANY_COMBINATION,
                    /* um */ PronPassword::ANY_COMBINATION,
                    /* un */ PronPassword::ANY_COMBINATION,
                    /* uo */ PronPassword::NOT_BEGIN | PronPassword::BRAKE,
                    /* up */ PronPassword::ANY_COMBINATION,
                    /* ur */ PronPassword::ANY_COMBINATION,
                    /* us */ PronPassword::ANY_COMBINATION,
                    /* ut */ PronPassword::ANY_COMBINATION,
                    /* uu */ PronPassword::ILLEGAL_PAIR,
                    /* uv */ PronPassword::ANY_COMBINATION,
                    /* uw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ux */ PronPassword::ANY_COMBINATION,
                    /* uy */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* uz */ PronPassword::ANY_COMBINATION,
                    /* uch */ PronPassword::ANY_COMBINATION,
                    /* ugh */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* uph */ PronPassword::ANY_COMBINATION,
                    /* urh */ PronPassword::ILLEGAL_PAIR,
                    /* ush */ PronPassword::ANY_COMBINATION,
                    /* uth */ PronPassword::ANY_COMBINATION,
                    /* uwh */ PronPassword::ILLEGAL_PAIR,
                    /* uqu */ PronPassword::BRAKE | PronPassword::NOT_END,
                    /* uck */ PronPassword::ANY_COMBINATION ),
                array(/* va */ PronPassword::ANY_COMBINATION,
                    /* vb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ve */ PronPassword::ANY_COMBINATION,
                    /* vf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vi */ PronPassword::ANY_COMBINATION,
                    /* vj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vl */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vo */ PronPassword::ANY_COMBINATION,
                    /* vp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vr */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vs */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vt */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vu */ PronPassword::ANY_COMBINATION,
                    /* vv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vx */ PronPassword::ILLEGAL_PAIR,
                    /* vy */ PronPassword::NOT_BEGIN,
                    /* vz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vrh */ PronPassword::ILLEGAL_PAIR,
                    /* vsh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vwh */ PronPassword::ILLEGAL_PAIR,
                    /* vqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* vck */ PronPassword::ILLEGAL_PAIR ),
                array(/* wa */ PronPassword::ANY_COMBINATION,
                    /* wb */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* wc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* wd */ PronPassword::NOT_BEGIN | PronPassword::PREFIX | PronPassword::END,
                    /* we */ PronPassword::ANY_COMBINATION,
                    /* wf */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* wg */ PronPassword::NOT_BEGIN | PronPassword::PREFIX | PronPassword::END,
                    /* wh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* wi */ PronPassword::ANY_COMBINATION,
                    /* wj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* wk */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* wl */ PronPassword::NOT_BEGIN | PronPassword::PREFIX | PronPassword::SUFFIX,
                    /* wm */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* wn */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* wo */ PronPassword::ANY_COMBINATION,
                    /* wp */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* wr */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* ws */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* wt */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* wu */ PronPassword::ANY_COMBINATION,
                    /* wv */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* ww */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* wx */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* wy */ PronPassword::ANY_COMBINATION,
                    /* wz */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* wch */ PronPassword::NOT_BEGIN,
                    /* wgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* wph */ PronPassword::NOT_BEGIN,
                    /* wrh */ PronPassword::ILLEGAL_PAIR,
                    /* wsh */ PronPassword::NOT_BEGIN,
                    /* wth */ PronPassword::NOT_BEGIN,
                    /* wwh */ PronPassword::ILLEGAL_PAIR,
                    /* wqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* wck */ PronPassword::NOT_BEGIN ),
                array(/* xa */ PronPassword::NOT_BEGIN,
                    /* xb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xe */ PronPassword::NOT_BEGIN,
                    /* xf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xi */ PronPassword::NOT_BEGIN,
                    /* xj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xl */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xo */ PronPassword::NOT_BEGIN,
                    /* xp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xr */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xs */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xt */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xu */ PronPassword::NOT_BEGIN,
                    /* xv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xx */ PronPassword::ILLEGAL_PAIR,
                    /* xy */ PronPassword::NOT_BEGIN,
                    /* xz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xrh */ PronPassword::ILLEGAL_PAIR,
                    /* xsh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xwh */ PronPassword::ILLEGAL_PAIR,
                    /* xqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* xck */ PronPassword::ILLEGAL_PAIR ),
                array(/* ya */ PronPassword::ANY_COMBINATION,
                    /* yb */ PronPassword::NOT_BEGIN,
                    /* yc */ PronPassword::NOT_BEGIN | PronPassword::NOT_END,
                    /* yd */ PronPassword::NOT_BEGIN,
                    /* ye */ PronPassword::ANY_COMBINATION,
                    /* yf */ PronPassword::NOT_BEGIN | PronPassword::NOT_END,
                    /* yg */ PronPassword::NOT_BEGIN,
                    /* yh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* yi */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* yj */ PronPassword::NOT_BEGIN | PronPassword::NOT_END,
                    /* yk */ PronPassword::NOT_BEGIN,
                    /* yl */ PronPassword::NOT_BEGIN | PronPassword::NOT_END,
                    /* ym */ PronPassword::NOT_BEGIN,
                    /* yn */ PronPassword::NOT_BEGIN,
                    /* yo */ PronPassword::ANY_COMBINATION,
                    /* yp */ PronPassword::NOT_BEGIN,
                    /* yr */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ys */ PronPassword::NOT_BEGIN,
                    /* yt */ PronPassword::NOT_BEGIN,
                    /* yu */ PronPassword::ANY_COMBINATION,
                    /* yv */ PronPassword::NOT_BEGIN | PronPassword::NOT_END,
                    /* yw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* yx */ PronPassword::NOT_BEGIN,
                    /* yy */ PronPassword::ILLEGAL_PAIR,
                    /* yz */ PronPassword::NOT_BEGIN,
                    /* ych */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ygh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* yph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* yrh */ PronPassword::ILLEGAL_PAIR,
                    /* ysh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* yth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ywh */ PronPassword::ILLEGAL_PAIR,
                    /* yqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* yck */ PronPassword::ILLEGAL_PAIR ),
                array(/* za */ PronPassword::ANY_COMBINATION,
                    /* zb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ze */ PronPassword::ANY_COMBINATION,
                    /* zf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zi */ PronPassword::ANY_COMBINATION,
                    /* zj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zl */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zo */ PronPassword::ANY_COMBINATION,
                    /* zp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zr */ PronPassword::NOT_BEGIN | PronPassword::NOT_END,
                    /* zs */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zt */ PronPassword::NOT_BEGIN,
                    /* zu */ PronPassword::ANY_COMBINATION,
                    /* zv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zw */ PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* zx */ PronPassword::ILLEGAL_PAIR,
                    /* zy */ PronPassword::ANY_COMBINATION,
                    /* zz */ PronPassword::NOT_BEGIN,
                    /* zch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zrh */ PronPassword::ILLEGAL_PAIR,
                    /* zsh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zwh */ PronPassword::ILLEGAL_PAIR,
                    /* zqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* zck */ PronPassword::ILLEGAL_PAIR ),
                array(/* cha */ PronPassword::ANY_COMBINATION,
                    /* chb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* che */ PronPassword::ANY_COMBINATION,
                    /* chf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chi */ PronPassword::ANY_COMBINATION,
                    /* chj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chl */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cho */ PronPassword::ANY_COMBINATION,
                    /* chp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chr */ PronPassword::NOT_END,
                    /* chs */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cht */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chu */ PronPassword::ANY_COMBINATION,
                    /* chv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chw */ PronPassword::NOT_BEGIN | PronPassword::NOT_END,
                    /* chx */ PronPassword::ILLEGAL_PAIR,
                    /* chy */ PronPassword::ANY_COMBINATION,
                    /* chz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chch */ PronPassword::ILLEGAL_PAIR,
                    /* chgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chrh */ PronPassword::ILLEGAL_PAIR,
                    /* chsh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chwh */ PronPassword::ILLEGAL_PAIR,
                    /* chqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* chck */ PronPassword::ILLEGAL_PAIR ),
                array(/* gha */ PronPassword::ANY_COMBINATION,
                    /* ghb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghe */ PronPassword::ANY_COMBINATION,
                    /* ghf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghi */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* ghj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghl */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* gho */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* ghp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ghr */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghs */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* ght */ PronPassword::NOT_BEGIN | PronPassword::PREFIX,
                    /* ghu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghx */ PronPassword::ILLEGAL_PAIR,
                    /* ghy */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghgh */ PronPassword::ILLEGAL_PAIR,
                    /* ghph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghrh */ PronPassword::ILLEGAL_PAIR,
                    /* ghsh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghwh */ PronPassword::ILLEGAL_PAIR,
                    /* ghqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::PREFIX | PronPassword::NOT_END,
                    /* ghck */ PronPassword::ILLEGAL_PAIR ),
                array(/* pha */ PronPassword::ANY_COMBINATION,
                    /* phb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phe */ PronPassword::ANY_COMBINATION,
                    /* phf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phi */ PronPassword::ANY_COMBINATION,
                    /* phj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phl */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* phm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* pho */ PronPassword::ANY_COMBINATION,
                    /* php */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phr */ PronPassword::NOT_END,
                    /* phs */ PronPassword::NOT_BEGIN,
                    /* pht */ PronPassword::NOT_BEGIN,
                    /* phu */ PronPassword::ANY_COMBINATION,
                    /* phv */ PronPassword::NOT_BEGIN | PronPassword::NOT_END,
                    /* phw */ PronPassword::NOT_BEGIN | PronPassword::NOT_END,
                    /* phx */ PronPassword::ILLEGAL_PAIR,
                    /* phy */ PronPassword::NOT_BEGIN,
                    /* phz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phph */ PronPassword::ILLEGAL_PAIR,
                    /* phrh */ PronPassword::ILLEGAL_PAIR,
                    /* phsh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phwh */ PronPassword::ILLEGAL_PAIR,
                    /* phqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* phck */ PronPassword::ILLEGAL_PAIR ),
                array(/* rha */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* rhb */ PronPassword::ILLEGAL_PAIR,
                    /* rhc */ PronPassword::ILLEGAL_PAIR,
                    /* rhd */ PronPassword::ILLEGAL_PAIR,
                    /* rhe */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* rhf */ PronPassword::ILLEGAL_PAIR,
                    /* rhg */ PronPassword::ILLEGAL_PAIR,
                    /* rhh */ PronPassword::ILLEGAL_PAIR,
                    /* rhi */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* rhj */ PronPassword::ILLEGAL_PAIR,
                    /* rhk */ PronPassword::ILLEGAL_PAIR,
                    /* rhl */ PronPassword::ILLEGAL_PAIR,
                    /* rhm */ PronPassword::ILLEGAL_PAIR,
                    /* rhn */ PronPassword::ILLEGAL_PAIR,
                    /* rho */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* rhp */ PronPassword::ILLEGAL_PAIR,
                    /* rhr */ PronPassword::ILLEGAL_PAIR,
                    /* rhs */ PronPassword::ILLEGAL_PAIR,
                    /* rht */ PronPassword::ILLEGAL_PAIR,
                    /* rhu */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* rhv */ PronPassword::ILLEGAL_PAIR,
                    /* rhw */ PronPassword::ILLEGAL_PAIR,
                    /* rhx */ PronPassword::ILLEGAL_PAIR,
                    /* rhy */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* rhz */ PronPassword::ILLEGAL_PAIR,
                    /* rhch */ PronPassword::ILLEGAL_PAIR,
                    /* rhgh */ PronPassword::ILLEGAL_PAIR,
                    /* rhph */ PronPassword::ILLEGAL_PAIR,
                    /* rhrh */ PronPassword::ILLEGAL_PAIR,
                    /* rhsh */ PronPassword::ILLEGAL_PAIR,
                    /* rhth */ PronPassword::ILLEGAL_PAIR,
                    /* rhwh */ PronPassword::ILLEGAL_PAIR,
                    /* rhqu */ PronPassword::ILLEGAL_PAIR,
                    /* rhck */ PronPassword::ILLEGAL_PAIR ),
                array(/* sha */ PronPassword::ANY_COMBINATION,
                    /* shb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* shc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* shd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* she */ PronPassword::ANY_COMBINATION,
                    /* shf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* shg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* shh */ PronPassword::ILLEGAL_PAIR,
                    /* shi */ PronPassword::ANY_COMBINATION,
                    /* shj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* shk */ PronPassword::NOT_BEGIN,
                    /* shl */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* shm */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* shn */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* sho */ PronPassword::ANY_COMBINATION,
                    /* shp */ PronPassword::NOT_BEGIN,
                    /* shr */ PronPassword::BEGIN | PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* shs */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* sht */ PronPassword::SUFFIX,
                    /* shu */ PronPassword::ANY_COMBINATION,
                    /* shv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* shw */ PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* shx */ PronPassword::ILLEGAL_PAIR,
                    /* shy */ PronPassword::ANY_COMBINATION,
                    /* shz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* shch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* shgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* shph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* shrh */ PronPassword::ILLEGAL_PAIR,
                    /* shsh */ PronPassword::ILLEGAL_PAIR,
                    /* shth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* shwh */ PronPassword::ILLEGAL_PAIR,
                    /* shqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* shck */ PronPassword::ILLEGAL_PAIR ),
                array(/* tha */ PronPassword::ANY_COMBINATION,
                    /* thb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* the */ PronPassword::ANY_COMBINATION,
                    /* thf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thi */ PronPassword::ANY_COMBINATION,
                    /* thj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thl */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* tho */ PronPassword::ANY_COMBINATION,
                    /* thp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thr */ PronPassword::NOT_END,
                    /* ths */ PronPassword::NOT_BEGIN | PronPassword::END,
                    /* tht */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thu */ PronPassword::ANY_COMBINATION,
                    /* thv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thw */ PronPassword::SUFFIX | PronPassword::NOT_END,
                    /* thx */ PronPassword::ILLEGAL_PAIR,
                    /* thy */ PronPassword::ANY_COMBINATION,
                    /* thz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thrh */ PronPassword::ILLEGAL_PAIR,
                    /* thsh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thth */ PronPassword::ILLEGAL_PAIR,
                    /* thwh */ PronPassword::ILLEGAL_PAIR,
                    /* thqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* thck */ PronPassword::ILLEGAL_PAIR ),
                array(/* wha */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* whb */ PronPassword::ILLEGAL_PAIR,
                    /* whc */ PronPassword::ILLEGAL_PAIR,
                    /* whd */ PronPassword::ILLEGAL_PAIR,
                    /* whe */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* whf */ PronPassword::ILLEGAL_PAIR,
                    /* whg */ PronPassword::ILLEGAL_PAIR,
                    /* whh */ PronPassword::ILLEGAL_PAIR,
                    /* whi */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* whj */ PronPassword::ILLEGAL_PAIR,
                    /* whk */ PronPassword::ILLEGAL_PAIR,
                    /* whl */ PronPassword::ILLEGAL_PAIR,
                    /* whm */ PronPassword::ILLEGAL_PAIR,
                    /* whn */ PronPassword::ILLEGAL_PAIR,
                    /* who */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* whp */ PronPassword::ILLEGAL_PAIR,
                    /* whr */ PronPassword::ILLEGAL_PAIR,
                    /* whs */ PronPassword::ILLEGAL_PAIR,
                    /* wht */ PronPassword::ILLEGAL_PAIR,
                    /* whu */ PronPassword::ILLEGAL_PAIR,
                    /* whv */ PronPassword::ILLEGAL_PAIR,
                    /* whw */ PronPassword::ILLEGAL_PAIR,
                    /* whx */ PronPassword::ILLEGAL_PAIR,
                    /* why */ PronPassword::BEGIN | PronPassword::NOT_END,
                    /* whz */ PronPassword::ILLEGAL_PAIR,
                    /* whch */ PronPassword::ILLEGAL_PAIR,
                    /* whgh */ PronPassword::ILLEGAL_PAIR,
                    /* whph */ PronPassword::ILLEGAL_PAIR,
                    /* whrh */ PronPassword::ILLEGAL_PAIR,
                    /* whsh */ PronPassword::ILLEGAL_PAIR,
                    /* whth */ PronPassword::ILLEGAL_PAIR,
                    /* whwh */ PronPassword::ILLEGAL_PAIR,
                    /* whqu */ PronPassword::ILLEGAL_PAIR,
                    /* whck */ PronPassword::ILLEGAL_PAIR ),
                array(/* qua */ PronPassword::ANY_COMBINATION,
                    /* qub */ PronPassword::ILLEGAL_PAIR,
                    /* quc */ PronPassword::ILLEGAL_PAIR,
                    /* qud */ PronPassword::ILLEGAL_PAIR,
                    /* que */ PronPassword::ANY_COMBINATION,
                    /* quf */ PronPassword::ILLEGAL_PAIR,
                    /* qug */ PronPassword::ILLEGAL_PAIR,
                    /* quh */ PronPassword::ILLEGAL_PAIR,
                    /* qui */ PronPassword::ANY_COMBINATION,
                    /* quj */ PronPassword::ILLEGAL_PAIR,
                    /* quk */ PronPassword::ILLEGAL_PAIR,
                    /* qul */ PronPassword::ILLEGAL_PAIR,
                    /* qum */ PronPassword::ILLEGAL_PAIR,
                    /* qun */ PronPassword::ILLEGAL_PAIR,
                    /* quo */ PronPassword::ANY_COMBINATION,
                    /* qup */ PronPassword::ILLEGAL_PAIR,
                    /* qur */ PronPassword::ILLEGAL_PAIR,
                    /* qus */ PronPassword::ILLEGAL_PAIR,
                    /* qut */ PronPassword::ILLEGAL_PAIR,
                    /* quu */ PronPassword::ILLEGAL_PAIR,
                    /* quv */ PronPassword::ILLEGAL_PAIR,
                    /* quw */ PronPassword::ILLEGAL_PAIR,
                    /* qux */ PronPassword::ILLEGAL_PAIR,
                    /* quy */ PronPassword::ILLEGAL_PAIR,
                    /* quz */ PronPassword::ILLEGAL_PAIR,
                    /* quch */ PronPassword::ILLEGAL_PAIR,
                    /* qugh */ PronPassword::ILLEGAL_PAIR,
                    /* quph */ PronPassword::ILLEGAL_PAIR,
                    /* qurh */ PronPassword::ILLEGAL_PAIR,
                    /* qush */ PronPassword::ILLEGAL_PAIR,
                    /* quth */ PronPassword::ILLEGAL_PAIR,
                    /* quwh */ PronPassword::ILLEGAL_PAIR,
                    /* ququ */ PronPassword::ILLEGAL_PAIR,
                    /* quck */ PronPassword::ILLEGAL_PAIR ),
                array(/* cka */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckb */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckc */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckd */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cke */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckf */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckg */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cki */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckj */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckk */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckl */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckm */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckn */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cko */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckp */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckr */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cks */ PronPassword::NOT_BEGIN,
                    /* ckt */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* cku */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckv */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckw */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckx */ PronPassword::ILLEGAL_PAIR,
                    /* cky */ PronPassword::NOT_BEGIN,
                    /* ckz */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckch */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckgh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckph */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckrh */ PronPassword::ILLEGAL_PAIR,
                    /* cksh */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckth */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckwh */ PronPassword::ILLEGAL_PAIR,
                    /* ckqu */ PronPassword::NOT_BEGIN | PronPassword::BRAKE | PronPassword::NOT_END,
                    /* ckck */ PronPassword::ILLEGAL_PAIR)
            );

    }

    /**
     * @param $minLen int Minimum Length of password
     * @param null int Maximum Length of password, optional, if left out it will be the same as $minLen
     * @return array returns array of the = array($password, $pronounciation_key);
     * @throws \Exception
     */
    public function genPass($minLen, $maxLen = null) {
        if($maxLen == null) {
            $maxLen = $minLen;
        }
        if($minLen > $maxLen) {
            throw new \Exception("\$minLen of $minLen cannot be greater than \$maxLen of $maxLen");
        }

        if($maxLen == 0) {
            return array("","");
        }
        $this->maxRetries = (4 * $maxLen + (count($this->rules)/count($this->digram)));

        return $this->genWord(mt_rand($minLen, $maxLen));
    }

    protected function genWord($pwlen) {
        $tries = 0;
        $wordLength = 0;
        $wordSize = 0;
        $wordUnits = array();
        $word = "";
        $hyphenatedWord = "";

        while($wordLength < $pwlen) {
            list($syllable, $unitsInSyllable) = $this->genSyllable($pwlen - $wordLength);
            $syllableSize = strlen($syllable);

            for($wordPlace = 0; $wordPlace <= $syllableSize; $wordPlace++) {
                if(isset($unitsInSyllable[$wordPlace]))
                    $wordUnits[$wordSize + $wordPlace] = $unitsInSyllable[$wordPlace];
            }
            $wordSize += $syllableSize + 1;
            if ($this->improperWord($wordUnits, $wordSize) ||
                (($wordLength == 0) && $this->haveInitialY($unitsInSyllable, $syllableSize)) ||
                (($wordLength + $syllableSize == $pwlen) && $this->haveFinalSplit($unitsInSyllable, $syllableSize))) {
                $wordSize -= $syllableSize + 1;
            } else {
                if ($wordLength == 0) {
                    $word .= $syllable;
                    if ($syllableSize == 1) {
                        $hyph = $this->symb2name($syllable);
                        $hyphenatedWord .= $hyph;
                    } else {
                        $hyphenatedWord = strtoupper($syllable);
                    }
                } else {
                    $word .= $syllable;
                    $hyphenatedWord .= "-";
	                if ($syllableSize == 1) {
                        $hyph = $this->symb2name($syllable);
                        $hyphenatedWord .= $hyph;
	                } else {
                        $hyphenatedWord .= strtoupper($syllable);
                    }

                }
                $wordLength += $syllableSize;
            }

            $tries++;
            if ($tries > $this->maxRetries) {
                $wordLength = 0;
                $wordSize = 0;
                $tries = 0;
                $word = "";
                $hyphenatedWord = "";
            }
        }

        return array($word, $hyphenatedWord);
    }

    protected function genSyllable($pwlen) {
        $lastUnit = 0;
        $holdSavedUnit = 0;
        $savedPair = array();
        $unitsInSyllable = array();

        do {

            $tries = 0;
            $savedUnit = $holdSavedUnit;
            $vowelCount = 0;
            $currentUnit = 0;
            $lengthLeft = $pwlen;
            $wantAnotherUnit = true;
            $syllable = "";
            do {
                $wantVowel = false;
                do {
                    /*
                    * If there are saved_unit's from the previous
                    * syllable, use them up first.
                    */
                    if ($savedUnit != 0) {
                        /*
                        * If there were two saved units, the first is
                        * guaranteed (by checks performed in the previous
                        * syllable) to be valid.  We ignore the checks
                        * and place it in this syllable manually.
                        */
                        if ($savedUnit == 2) {
                            $unitsInSyllable[0] = $savedPair[1];
                            if ($this->rules[$savedPair[1]][1] & PronPassword::VOWEL) {
                                $vowelCount++;
                            }
                            $currentUnit++;
                            $syllable .= $this->rules[$savedPair[1]][0];
                            $lengthLeft -= strlen($syllable);
                        }

                        /*
                        * The unit becomes the last unit checked in the
                        * previous syllable.
                        */
                        $unit = $savedPair[0];

                        /*
                        * The saved units have been used.  Do not try to
                        * reuse them in this syllable (unless this particular
                        * syllable is rejected at which point we start to rebuild
                        * it with these same saved units.
                        */
                        $savedUnit = 0;
                    } else {
                        /*
                        * If we don't have to scoff the saved units,
                        * we generate a Random one.  If we know it has
                        * to be a vowel, we get one rather than looping
                        * through until one shows up.
                        */
                        if ($wantVowel) {
                            $unit = $this->randomUnit(PronPassword::VOWEL);
                        } else {
                            $unit = $this->randomUnit(PronPassword::NO_SPECIAL_RULE);
                        }
                    }
                    $lengthLeft -= strlen($this->rules[$unit][0]);
                    /*
                    * Prevent having a word longer than expected.
                    */
                    if ($lengthLeft < 0) {
                        $ruleBroken = true;
                    } else {
                        $ruleBroken = false;
                    }

                    /*
                    * First unit of syllable.  This is special because the
                    * digram tests require 2 units and we don't have that yet.
                    * Nevertheless, we can perform some checks.
                    */
                    if ($currentUnit == 0) {
                        /*
                        * If the shouldn't begin a syllable, don't
                        * use it.
                        */
                        if ($this->rules[$unit][1] & PronPassword::NOT_BEGIN_SYLLABLE) {
                            $ruleBroken = true;
                        } else {
                            /*
                            * If this is the last unit of a word,
                            * we have a one unit syllable.  Since each
                            * syllable must have a vowel, we make sure
                            * the unit is a vowel.  Otherwise, we
                            * discard it.
                            */
                            if ($lengthLeft == 0) {
                                if ($this->rules[$unit][1] & PronPassword::VOWEL) {
                                    $wantAnotherUnit = false;
                                } else {
                                    $ruleBroken = true;
                                }
                            }
                        }
                    } else {
                        /*
                        * There are some digram tests that are
                        * universally true.  We test them out.
                        */

                        /*
                        * Reject ILLEGAL_PAIRS of units.
                        */
                        if (($this->allowed(PronPassword::ILLEGAL_PAIR, $unitsInSyllable, $currentUnit, $unit)) ||

                            /*
                            * Reject units that will be split between syllables
                            * when the syllable has no vowels in it.
                            */
                            ($this->allowed(PronPassword::BRAKE, $unitsInSyllable, $currentUnit, $unit) && ($vowelCount == 0)) ||

                            /*
                            * Reject a unit that will end a syllable when no
                            * previous unit was a vowel and neither is this one.
                            */
                            ($this->allowed(PronPassword::END, $unitsInSyllable, $currentUnit, $unit) && ($vowelCount == 0) &&
                                !($this->rules[$unit][1] & PronPassword::VOWEL))
                        ) {
                            $ruleBroken = true;
                        }

                        if ($currentUnit == 1) {
                            /*
                            * Reject the unit if we are at te starting digram of
                            * a syllable and it does not fit.
                            */
                            if ($this->allowed(PronPassword::NOT_BEGIN, $unitsInSyllable, $currentUnit, $unit)) {
                                $ruleBroken = true;
                            }
                        } else {
                            /*
                            * We are not at the start of a syllable.
                            * Save the previous unit for later tests.
                            */
                            $lastUnit = $unitsInSyllable[$currentUnit - 1];

                            /*
                            * Do not allow syllables where the first letter is y
                            * and the next pair can begin a syllable.  This may
                            * lead to splits where y is left alone in a syllable.
                            * Also, the combination does not sound to good even
                            * if not split.
                            */
                            if ((($currentUnit == 2) &&
                                ($this->allowed(PronPassword::BEGIN, $unitsInSyllable, $currentUnit, $unit)) &&
                                ($this->rules[$unitsInSyllable[0]][1] &
                                    PronPassword::ALTERNATE_VOWEL)) ||

                                /*
                                * If this is the last unit of a word, we should
                                * reject any digram that cannot end a syllable.
                                */
                                ($this->allowed(PronPassword::NOT_END, $unitsInSyllable, $currentUnit, $unit) &&
                                    ($lengthLeft == 0)) ||

                                /*
                                * Reject the unit if the digram it forms wants
                                * to break the syllable, but the resulting
                                * digram that would end the syllable is not
                                * allowed to end a syllable.
                                */
                                ($this->allowed(PronPassword::BRAKE, $unitsInSyllable, $currentUnit, $unit) &&
                                    ($this->digram[$unitsInSyllable
                                    [$currentUnit - 2]]
                                    [$lastUnit] &
                                        PronPassword::NOT_END)) ||

                                /*
                                * Reject the unit if the digram it forms
                                * expects a vowel preceding it and there is
                                * none.
                                */
                                ($this->allowed(PronPassword::PREFIX, $unitsInSyllable, $currentUnit, $unit) &&
                                    !($this->rules[$unitsInSyllable
                                    [$currentUnit - 2]][1] &
                                        PronPassword::VOWEL))
                            ) {
                                $ruleBroken = true;
                            }

                            /*
                            * The following checks occur when the current unit
                            * is a vowel and we are not looking at a word ending
                            * with an e.
                            */
                            if (!$ruleBroken &&
                                ($this->rules[$unit][1] & PronPassword::VOWEL) &&
                                (($lengthLeft > 0) ||
                                    !($this->rules[$lastUnit][1] &
                                        PronPassword::NO_FINAL_SPLIT))
                            ) {
                                /*
                                * Don't allow 3 consecutive vowels in a
                                * syllable.  Although some words formed like this
                                * are OK, like beau, most are not.
                                */
                                if (($vowelCount > 1) &&
                                    ($this->rules[$lastUnit][1] & PronPassword::VOWEL)
                                )
                                    $ruleBroken = true;
                                else
                                    /*
                                    * Check for the case of
                                    * vowels-consonants-vowel, which is only
                                    * legal if the last vowel is an e and we are
                                    * the end of the word (wich is not
                                    * happening here due to a previous check.
                                    */
                                    if (($vowelCount != 0) &&
                                        !($this->rules[$lastUnit][1] & PronPassword::VOWEL)
                                    ) {
                                        /*
                                        * Try to save the vowel for the next
                                        * syllable, but if the syllable left here
                                        * is not proper (i.e., the resulting last
                                        * digram cannot legally end it), just
                                        * discard it and try for another.
                                        */
                                        if ($this->digram[$unitsInSyllable
                                        [$currentUnit - 2]]
                                        [$lastUnit] &
                                            PronPassword::NOT_END
                                        )
                                            $ruleBroken = true;
                                        else
                                        {
                                            $savedUnit = 1;
                                            $savedPair[0] = $unit;
                                            $wantAnotherUnit = false;
                                        }
                                    }
                            }
                        }

                        /*
                        * The unit picked and the digram formed are legal.
                        * We now determine if we can end the syllable.  It may,
                        * in some cases, mean the last unit(s) may be deferred to
                        * the next syllable.  We also check here to see if the
                        * digram formed expects a vowel to follow.
                        */
                        if (!$ruleBroken && $wantAnotherUnit) {
                            /*
                            * This word ends in a silent e.
                            */
                            /******/
                            if ((($vowelCount != 0) &&
                                ($this->rules[$unit][1] & PronPassword::NO_FINAL_SPLIT) &&
                                ($lengthLeft == 0) &&
                                !($this->rules[$lastUnit][1] & PronPassword::VOWEL)) ||

                                /*
                                * This syllable ends either because the digram
                                * is an END pair or we would otherwise exceed
                                * the length of the word.
                                */
                                ($this->allowed(PronPassword::END, $unitsInSyllable, $currentUnit, $unit) || ($lengthLeft == 0))
                            ) {
                                $wantAnotherUnit = false;
                            }
                            else
                                /*
                                * Since we have a vowel in the syllable
                                * already, if the digram calls for the end of the
                                * syllable, we can legally split it off. We also
                                * make sure that we are not at the end of the
                                * dangerous because that syllable may not have
                                * vowels, or it may not be a legal syllable end,
                                * and the retrying mechanism will loop infinitely
                                * with the same digram.
                                */
                                if (($vowelCount != 0) && ($lengthLeft > 0)) {
                                    /*
                                    * If we must begin a syllable, we do so if
                                    * the only vowel in THIS syllable is not part
                                    * of the digram we are pushing to the next
                                    * syllable.
                                    */
                                    if ($this->allowed(PronPassword::BEGIN, $unitsInSyllable, $currentUnit, $unit) &&
                                        ($currentUnit > 1) &&
                                        !(($vowelCount == 1) &&
                                            ($this->rules[$lastUnit][1] & PronPassword::VOWEL))
                                    ) {
                                        $savedUnit = 2;
                                        $savedPair[0] = $unit;
                                        $savedPair[1] = $lastUnit;
                                        $wantAnotherUnit = false;
                                    }
                                    else
                                        if ($this->allowed(PronPassword::BRAKE, $unitsInSyllable, $currentUnit, $unit)) {
                                            $savedUnit = 1;
                                            $savedPair[0] = $unit;
                                            $wantAnotherUnit = false;
                                        }
                                }
                                else
                                    if ($this->allowed(PronPassword::SUFFIX, $unitsInSyllable, $currentUnit, $unit)) {
                                        $wantVowel = true;
                                    }
                        }
                    }
                    $tries++;

                    /*
                    * If this unit was illegal, redetermine the amount of
                    * letters left to go in the word.
                    */
                    if ($ruleBroken) {
                        $lengthLeft += strlen($this->rules[$unit][0]);
                    }
                } while ($ruleBroken && $tries <= $this->maxRetries);
                if ($tries <= $this->maxRetries) {
                    if (($this->rules[$unit][1] & PronPassword::VOWEL) && (($currentUnit > 0) || !($this->rules[$unit][1] & PronPassword::ALTERNATE_VOWEL))) {
                        $vowelCount++;
                    }

                    switch ($savedUnit) {
                        case 0:
                            $unitsInSyllable[$currentUnit] = $unit;
                            $syllable .= $this->rules[$unit][0];
                            break;
                        case 1:
                            $currentUnit--;
                            break;
                        case 2:
                            $syllable = substr($syllable, 0, strlen($this->rules[$lastUnit][0]) * -1);
                            $lengthLeft += strlen($this->rules[$lastUnit][0]);
                            $currentUnit -= 2;
                            break;
                    }
                } else {
                    $ruleBroken = true;
                }
                $syllableLength = $currentUnit;
                $currentUnit++;
            } while ($tries <= $this->maxRetries && $wantAnotherUnit);
        } while ($ruleBroken || $this->illegalPlacement($unitsInSyllable, $syllableLength));
        return array($syllable, $unitsInSyllable);
    }

    protected function improperWord($units, $wordSize) {
        $failure = false;
        for ($unitCount = 0; !$failure && ($unitCount < $wordSize); $unitCount++) {
            /*
            * Check for ILLEGAL_PAIR.  This should have been caught
            * for units within a syllable, but in some cases it
            * would have gone unnoticed for units between syllables
            * (e.g., when saved_unit's in gen_syllable() were not
            * used).
            */
            if (isset($units[$unitCount], $units[$unitCount - 1]) && ($unitCount != 0) && ($this->digram[$units[$unitCount - 1]][$units[$unitCount]] & PronPassword::ILLEGAL_PAIR)) {
                $failure = true;
            }

            /*
            * Check for consecutive vowels or consonants.  Because
            * the initial y of a syllable is treated as a consonant
            * rather than as a vowel, we exclude y from the first
            * vowel in the vowel test.  The only problem comes when
            * y ends a syllable and two other vowels start the next,
            * like fly-oint.  Since such words are still
            * pronounceable, we accept this.
            */
            if (!$failure && ($unitCount >= 2)) {
                /*
                * Vowel check.
                */
                if ((((isset($units[$unitCount - 2]) && $this->rules[$units[$unitCount - 2]][1] & PronPassword::VOWEL) &&
                       !(isset($units[$unitCount - 2]) && $this->rules[$units[$unitCount - 2]][1] & PronPassword::ALTERNATE_VOWEL)) &&
                   (isset($units[$unitCount - 1]) && $this->rules[$units[$unitCount - 1]][1] & PronPassword::VOWEL) &&
                   (isset($units[$unitCount]) && $this->rules[$units[$unitCount]][1] & PronPassword::VOWEL)) ||
                /*
                * Consonant check.
                */
                  (!(isset($units[$unitCount - 2]) && $this->rules[$units[$unitCount - 2]][1] & PronPassword::VOWEL) &&
                   !(isset($units[$unitCount - 1]) && $this->rules[$units[$unitCount - 1]][1] & PronPassword::VOWEL) &&
                   !(isset($units[$unitCount]) && $this->rules[$units[$unitCount]][1] & PronPassword::VOWEL)))
                $failure = true;
            }
        }

        return $failure;
    }

    protected function haveInitialY($units, $unitSize) {
        $vowelCount = 0;
        $normalVowelCount = 0;

        for ($unitCount = 0; $unitCount <= $unitSize; $unitCount++) {
            /*
            * Count vowels.
            */
            if (isset($units[$unitCount]) && $this->rules[$units[$unitCount]][1] & PronPassword::VOWEL) {
             $vowelCount++;

             /*
              * Count the vowels that are not: 1. y, 2. at the start of
              * the word.
              */
              if (!($this->rules[$units[$unitCount]][1] & PronPassword::ALTERNATE_VOWEL) || ($unitCount != 0)) {
                  $normalVowelCount++;
              }

            }

        }
        return (($vowelCount <= 1) && ($normalVowelCount == 0));
    }

    protected function haveFinalSplit($units, $unitSize) {
        $vowelCount = 0;

        /*
        *    Count all the vowels in the word.
        */
        for ($unitCount = 0; $unitCount <= $unitSize; $unitCount++) {
            if (isset($units[$unitCount]) && $this->rules[$units[$unitCount]][1] & PronPassword::VOWEL)
                $vowelCount++;
        }

        /*
        * Return TRUE iff the only vowel was e, found at the end if the
        * word.
        */
        return (($vowelCount == 1) &&
         (isset($units[$unitSize]) && $this->rules[$units[$unitSize]][1] & PronPassword::NO_FINAL_SPLIT));
    }

    protected function illegalPlacement($units, $pwlen) {
        $vowelCount = 0;
        $failure = false;

        for($unit_count = 0; !$failure && ($unit_count <= $pwlen); $unit_count++) {
            if($unit_count >= 1) {
                if((!($this->rules[$units[$unit_count - 1]][1] & PronPassword::VOWEL) &&
               ($this->rules[$units[$unit_count]][1] & PronPassword::VOWEL) &&
               !(($this->rules[$units[$unit_count]][1] & PronPassword::NO_FINAL_SPLIT) &&
                   ($unit_count == $pwlen)) && ($vowelCount != 0)) ||
         /*
          * Perform these checks when we have at least 3 units.
          */
              (($unit_count >= 2) &&

                  /*
                   * Disallow 3 consecutive consonants.
                   */
               ((!($this->rules[$units[$unit_count - 2]] & PronPassword::VOWEL) &&
                    !($this->rules[$units[$unit_count - 1]][1] &
                    PronPassword::VOWEL) &&
                    !($this->rules[$units[$unit_count]][1] &
                    PronPassword::VOWEL)) ||

                   /*
                    * Disallow 3 consecutive vowels, where the first is
                    * not a y.
                    */
                   ((($this->rules[$units[$unit_count - 2]][1] &
                    PronPassword::VOWEL) &&
                        !(($this->rules[$units[0]][1] &
                    PronPassword::ALTERNATE_VOWEL) &&
                         ($unit_count == 2))) &&
                    ($this->rules[$units[$unit_count - 1]][1] &
                    PronPassword::VOWEL) &&
                    ($this->rules[$units[$unit_count]][1] &
                    PronPassword::VOWEL))))) {
                    $failure = true;
                }
            }

            /*
            * Count the vowels in the syllable.  As mentioned somewhere
            * above, exclude the initial y of a syllable.  Instead,
            * treat it as a consonant.
            */
            if (($this->rules[$units[$unit_count]][1] & PronPassword::VOWEL) &&
            !(($this->rules[$units[0]][1] & PronPassword::ALTERNATE_VOWEL) &&
              ($unit_count == 0) && ($pwlen != 0))) {
                 $vowelCount++;
            }
        }
        return $failure;
    }

    private function allowed($type, $unitsInSyllable, $currentUnit, $unit) {
         return ($this->digram[$unitsInSyllable[$currentUnit -1]][$unit] & $type);
    }

    static private $numbers =
    array(
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        5, 5, 5, 5, 5, 5, 5, 5,
        6, 6, 6, 6, 6, 6, 6, 6,
        7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        9, 9, 9, 9, 9, 9, 9, 9,
        10, 10, 10, 10, 10, 10, 10, 10,
        11, 11, 11, 11, 11, 11,
        12, 12, 12, 12, 12, 12,
        13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
        14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
        15, 15, 15, 15, 15, 15,
        16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
        17, 17, 17, 17, 17, 17, 17, 17,
        18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
        19, 19, 19, 19, 19, 19,
        20, 20, 20, 20, 20, 20, 20, 20,
        21, 21, 21, 21, 21, 21, 21, 21,
        22,
        23, 23, 23, 23, 23, 23, 23, 23,
        24,
        25,
        26,
        27,
        28,
        29, 29,
        30,
        31,
        32,
        33
    );
    static private $vowelNumber = array(0, 0, 4, 4, 4, 8, 8, 14, 14, 19, 19, 23);
    private function randomUnit($type) {

        /*
         * Sometimes, we are asked to explicitly get a vowel (i.e., if
         * a digram pair expects one following it).  This is a shortcut
         * to do that and avoid looping with rejected consonants.
         */
        if($type & PronPassword::VOWEL) {
            $number = PronPassword::$vowelNumber[array_rand(PronPassword::$vowelNumber)];
        } else {
         /*
          * Get any letter according to the English distribution.
          */
         $number = PronPassword::$numbers[array_rand(PronPassword::$numbers)];
        }
        return $number;
    }

    protected function symb2name($syllable) {
         $symNames = array(
          array('1',"ONE"),
          array('2',"TWO"),
          array('3',"THREE"),
          array('4',"FOUR"),
          array('5',"FIVE"),
          array('6',"SIX"),
          array('7',"SEVEN"),
          array('8',"EIGHT"),
          array('9',"NINE"),
          array('0',"ZERO"),
          array(33, "EXCLAMATION_POINT"),
          array(34, "QUOTATION_MARK"),
          array(35, "CROSSHATCH"),
          array(36, "DOLLAR_SIGN"),
          array(37, "PERCENT_SIGN"),
          array(38, "AMPERSAND"),
          array(39, "APOSTROPHE"),
          array(40, "LEFT_PARENTHESIS"),
          array(41, "RIGHT_PARENTHESIS"),
          array(42, "ASTERISK"),
          array(43, "PLUS_SIGN"),
          array(44, "COMMA"),
          array(45, "HYPHEN"),
          array(46, "PERIOD"),
          array(47, "SLASH"),
          array(58, "COLON"),
          array(59, "SEMICOLON"),
          array(60, "LESS_THAN"),
          array(61, "EQUAL_SIGN"),
          array(62, "GREATER_THAN"),
          array(63, "QUESTION_MARK"),
          array(64, "AT_SIGN"),
          array(91, "LEFT_BRACKET"),
          array(92, "BACKSLASH"),
          array(93, "RIGHT_BRACKET"),
          array(94, "CIRCUMFLEX"),
          array(95, "UNDERSCORE"),
          array(96, "GRAVE"),
          array(123, "LEFT_BRACE"),
          array(124, "VERTICAL_BAR"),
          array(125, "RIGHT_BRACE"),
          array(126, "TILDE")
        );
        $flag = false;
        $hsyllable = "";

        if (strlen($syllable) == 1) {
            for ($i = 0; $i < 42; $i++) {
                if($syllable == $symNames[$i][0]) {
                     $hsyllable = $symNames[$i][1];
                    $flag = true;
                }
            }
            if ($flag != true)
                $hsyllable = strtoupper($syllable);
        }
        return $hsyllable;

    }
}