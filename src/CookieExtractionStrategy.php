<?php

namespace Perimeterx;

interface CookieExtractionStrategy
{
    public function getCookieData();
    public function getCookieChecksum();
    public function getScore();
}

namespace Perimeterx;

class CookieV1ExtractionStrategy implements CookieExtractionStrategy
{

    private $pxCookieData;
    private $cookieChecksum;

    public function __construct($pxCookieData) {
        $this->pxCookieData = $pxCookieData;
    }

    public function getCookieData() {
        return $this->pxCookieData;
    }

    public function getCookieChecksum($decodedCookie) {
        return $decodedCookie->h;
    }

    public function getScore($decodedScore) {
        return $decodedCookie->s->a;
    }

}

namespace Perimeterx;

class CookieV3ExtractionStrategy implements CookieExtractionStrategy
{
    private $pxCookieData;
    private $cookieChecksum;

    public function __construct($cookieChekcsum, $pxCookieData) {
        $this->cookieChecksum = $cookieChecksum;
        $this->pxCookieData = $pxCookieData;
    }

    public function getCookieData() {
        return $this->pxCookieData;

    }

    public function getCookieChecksum() {
        return $this->cookieChecksum;
    }

    public function getScore($decodedScore) {
        return $decodedCookie->s;
    }
}
?>
