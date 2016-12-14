<?php
namespace Perimeterx;

class CookieV3ExtractionStrategy implements CookieExtractionStrategy
{
    private $pxCookieData;
    private $cookieChecksum;

    public function __construct($cookieChekcsum, $pxCookieData) {
        error_log('checksum: ' . $cookieChecksum);
        error_log('cookie data: ' . $pxCookieData);
        $this->cookieChecksum = $cookieChecksum;
        $this->pxCookieData = $pxCookieData;
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
