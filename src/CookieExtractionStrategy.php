<?php

namespace Perimeterx;

interface CookieExtractionStrategy
{
    public function getCookieData();
    public function getCookieChecksum($decodedCookie);
    public function getScore($decodedCookie);
    public function getAction($decodedCookie);
}

?>
