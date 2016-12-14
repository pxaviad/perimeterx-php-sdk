<?php

namespace Perimeterx;

class PerimeterxCookie
{

    /**
     * @var object - cookie values extraction strategy
     */
    private $cookieExtractStrategy;

    /**
     * @var object - perimeterx configuration object
     */
    private $pxConfig;

    /**
     * @var PerimeterxContext
     */
    private $pxCtx;

    /**
     * @var string
     */
    private $cookieSecret;

    /**
     * @param $pxCtx PerimeterxContext - perimeterx context
     * @param $pxConfig array - perimeterx configurations
     */
    public function __construct($pxCtx, $pxConfig)
    {
        $splitCookie = explode(':', $pxCtx->getPxCookie());
        error_log('count :' . $count);
        if (count($splitCookie) === 4) {
            error_log('starting cookie v3 extration strategy');
            $this->cookieExtractStrategy = new CookieV3ExtractionStrategy($splitCookie[0], $splitCookie[1]);
        } else {
            $this->cookieExtractStrategy = new CookieV1ExtractionStrategy($pxCtx->getPxCookie());
        }
        $this->pxConfig = $pxConfig;
        $this->pxCtx = $pxCtx;
        $this->cookieSecret = $pxConfig['cookie_key'];
    }

    /**
     * @var \stdClass
     */
    private $decodedCookie;

    public function getDecodedCookie()
    {
        return $this->decodedCookie;
    }

    public function getTime()
    {
        return $this->getDecodedCookie()->t;
    }

    public function getScore()
    {
        return $this->cookieExtractStrategy->getScore($this->getDecodedCookie());
    }

    public function getUuid()
    {
        return $this->getDecodedCookie()->u;
    }

    public function getVid()
    {
        return $this->getDecodedCookie()->v;
    }

    public function getAction()
    {
        return $this->cookieExtractStrategy->getAction($this->decodedCookie);
    }

    private function getHmac()
    {
        return $this->cookieExtractStrategy->getCookieChecksum($this->decodedCookie);
    }

    private function getBaseHmacString() {
        if (isset($this->decodedCookie->s, $this->decodedCookie->s->a)) {
            return $this->getTime() . $this->decodedCookie->s->a . $this->getScore() . $this->getUuid() . $this->getVid();
        }
        return $this->getTime() . $this->getScore() . $this->getUuid() . $this->getVid();
    }

    /**
     * Checks if the cookie's score is above the configured blocking score
     *
     * @return bool
     */
    public function isHighScore()
    {
        return ($this->getScore() >= $this->pxConfig['blocking_score']);
    }

    /**
     * Checks if the cookie has expired
     *
     * @return bool
     */
    public function isExpired()
    {
        $dataTimeSec = $this->getTime() / 1000;

        return ($dataTimeSec < time());
    }

    /**
     * Checks that the cookie is secure via HMAC
     *
     * @return bool
     */
    public function isSecure()
    {
        $base_hmac_str = $this->getBaseHmacString();

        /* hmac string with ip - for backward support */
        $hmac_str_withip = $base_hmac_str . $this->pxCtx->getIp() . $this->pxCtx->getUserAgent();

        /* hmac string with no ip */
        $hmac_str_withoutip = $base_hmac_str . $this->pxCtx->getUserAgent();

        if ($this->isHmacValid($hmac_str_withoutip, $this->getHmac()) or $this->isHmacValid($hmac_str_withip, $this->getHmac())) {
            return true;
        }
        return false;
    }

    /**
     * Checks that the cookie was deserialized succcessfully, has not expired, and is secure
     *
     * @return bool
     */
    public function isValid()
    {
        return $this->deserialize() && !$this->isExpired() && $this->isSecure();
    }

    /**
     * Deserializes an encrypted and/or encoded cookie string.
     *
     * This must be called before using an instance.
     *
     * @return bool
     */
    public function deserialize()
    {
        // only deserialize once
        if ($this->decodedCookie !== null) {
            return true;
        }

        if ($this->pxConfig['encryption_enabled']) {
            $cookie = $this->decrypt();
        } else {
            $cookie = $this->decode();
        }
        $cookie = json_decode($cookie);
        if ($cookie == null) {
            return false;
        }

        if (!isset($cookie->t, $cookie->s, $cookie->s->b, $cookie->u, $cookie->v, $cookie->h)) {
            return false;
        }

        $this->decodedCookie = $cookie;

        return true;
    }

    private function getCookieData() {
        return $this->cookieExtractStrategy->getCookieData();
    }

    private function decrypt()
    {
        $ivlen = 16;
        $keylen = 32;
        $digest = 'sha256';

        $cookie = $this->getCookieData();
        error_log('cookie ' . $cookie);
        list($salt, $iterations, $cookie) = explode(":", $cookie);
        $iterations = intval($iterations);
        $salt = base64_decode($salt);
        $cookie = base64_decode($cookie);

        $derivation = hash_pbkdf2($digest, $this->cookieSecret, $salt, $iterations, $ivlen + $keylen, true);
        $key = substr($derivation, 0, $keylen);
        $iv = substr($derivation, $keylen);
        $cookie = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $cookie, MCRYPT_MODE_CBC, $iv);
        return $this->unpad($cookie);
    }

    private function unpad($str)
    {
        $len = mb_strlen($str);
        $pad = ord($str[$len - 1]);
        if ($pad && $pad < 16) {
            $pm = preg_match('/' . chr($pad) . '{' . $pad . '}$/', $str);
            if ($pm) {
                return mb_substr($str, 0, $len - $pad);
            }
        }
        return $str;
    }

    /**
     * @return string - decoded perimeterx cookie
     */
    private function decode()
    {
        $data_str = base64_decode($this->getCookieData());
        return json_decode($data_str);
    }

    private function isHmacValid($hmac_str, $cookie_hmac)
    {
        $hmac = hash_hmac('sha256', $hmac_str, $this->cookieSecret);

        if (function_exists('hash_equals')) {
            return hash_equals($hmac, $cookie_hmac);
        }

        // @see http://php.net/manual/en/function.hash-equals.php#115635
        if (strlen($hmac) != strlen($cookie_hmac)) {
            return false;
        } else {
            $res = $hmac ^ $cookie_hmac;
            $ret = false;
            for ($i = strlen($res) - 1; $i >= 0; $i--) {
                $ret |= ord($res[$i]);
            }

            return !$ret;
        }
    }
}
