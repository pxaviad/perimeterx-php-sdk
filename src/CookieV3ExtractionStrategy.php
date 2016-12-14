<?php
namespace Perimeterx;

class CookieV3ExtractionStrategy implements CookieExtractionStrategy
{
    private $pxCookieData;
    private $cookieChecksum;

    public function __construct($pxCookie) {
        $pos = strpos($pxCookie, ":");
        $this->cookieChecksum = substr($pxCookie, 0, $pos);
        $this->pxCookieData = substr($pxCookie, $pos + 1);
        error_log('checksum: ' . $this->cookieChecksum);
        error_log('cookie data: ' . $this->pxCookieData);
    }

    public function getCookieData() {
        return $this->pxCookieData;
    }

    public function getCookieChecksum($decryptedCookie) {
        return $this->cookieChecksum;
    }

    public function getScore($decodedCookie) {
        return $decodedCookie->s;
    }

    public function getAction($decodedCookie) {
        return $decryptedCookie->a;
    }

}

?>
