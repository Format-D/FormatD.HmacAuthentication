<?php

namespace FormatD\HmacAuthentication\Domain\Model;

use Neos\Flow\Annotations as Flow;

/**
 * @Flow\Scope("prototype")
 */
class HmacToken
{
    /**
     * @var array<string,string>
     */
    protected $payload;

    /**
     * @var string
     */
    protected $hmac;

    /**
     * @var int
     */
    protected $timestamp;

    public function __construct($payload = [], $hmac = null, $timestamp = null)
    {
        $this->payload = $payload;
        $this->hmac = $hmac;
        $this->timestamp = $timestamp;
    }

    /**
     * @param string $hmac
     */
    public function setHmac(string $hmac) {
        $this->hmac = $hmac;
    }

    /**
     * @param int $timestamp
     */
    public function setTimestamp(int $timestamp) {
        $this->timestamp = $timestamp;
    }

    /**
     * @param string $key
     * @param string $value
     */
    public function setPayloadEntry(string $key, string $value) {
        $this->payload[$key] = $value;
    }

    /**
     * @param string $key
     */
    public function hasPayloadEntry(string $key) {
        return array_key_exists($key, $this->payload);
    }

    /**
     * @param string $key
     * @return mixed|string
     */
    public function getPayloadEntry(string $key) {
        return $this->payload[$key];
    }

    /**
     * @return false|string
     */
    public function getHashData() {
        return json_encode($this->payload);
    }

    /**
     * @return int
     */
    public function getTimestamp() {
        return $this->timestamp;
    }

    /**
     * @return string
     */
    public function getHmac() {
        return $this->hmac;
    }

    /**
     * @return false|string
     */
    public function toJson() {
        return json_encode([
            'payload' => $this->payload,
            'hmac' => $this->hmac,
            'timestamp' => $this->timestamp
        ]);
    }

    /**
     * @param string $json
     * @return HmacToken
     */
    public static function FromJson(string $json) {
        $data = json_decode($json, true);
        $token = new HmacToken($data['payload'], $data['hmac'], $data['timestamp']);
        return $token;
    }
}