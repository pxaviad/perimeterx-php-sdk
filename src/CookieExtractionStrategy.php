<?php

namespace Perimeterx;

interface CookieExtractionStrategy
{
    public function getCookieData();
    public function getCookieChecksum();
    public function getScore();
}

?>
