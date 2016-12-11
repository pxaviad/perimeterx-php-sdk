<?php

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

    public function getScore($decodedCookie) {
        return $decodedCookie->s->b;
    }

    public function getAction($decodedCookie) {
        return '';
    }

}

?>
