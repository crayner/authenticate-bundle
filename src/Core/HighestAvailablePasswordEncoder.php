<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 21/03/2019
 * Time: 09:53
 */
namespace Crayner\Authenticate\Core;

use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Encoder\PlaintextPasswordEncoder;
use Symfony\Component\Security\Core\Encoder\SelfSaltingEncoderInterface;

/**
 * Class HighestAvailablePasswordEncoder
 * @package Crayner\Authenticate\Core
 */
class HighestAvailablePasswordEncoder implements PasswordEncoderInterface, SelfSaltingEncoderInterface
{
    private $allEncoders = [
        'argon2' => 16,
        'bcrypt' => 8,
        'sha256' => 4,
        'md5' => 2,
        'plain' => 1,
    ];
    /**
     * @var array|null
     */
    private $config;

    /**
     * @var PasswordEncoderInterface[]
     */
    private $encoders = [];

    /**
     * setConfiguration
     * @param array $config
     */
    public function setConfiguration(array $config)
    {
        $this->config = $config;
        $this->definedEncoders();

        $this->loadEncoders();
        $this->rehashPasswordRequired = null;
    }

    /**
     * encodePassword
     * @param string $raw
     * @param string $salt
     * @return string
     */
    public function encodePassword($raw, $salt)
    {
        $encoder = $this->getEncoder();
        return $encoder->encodePassword($raw, $salt);
    }

    /**
     * getEncoder
     * @return PasswordEncoderInterface
     */
    public function getEncoder(): PasswordEncoderInterface
    {
        return reset($this->encoders);
    }

    /**
     * @var bool|null
     */
    private $rehashPasswordRequired;

    /**
     * isPasswordValid
     * @param string $encoded
     * @param string $raw
     * @param string $salt
     * @return bool
     */
    public function isPasswordValid($encoded, $raw, $salt): bool
    {
        $this->rehashPasswordRequired = false;
        foreach($this->encoders as $encoder) {
            if (get_class($this->getEncoder()) !== get_class($encoder) && $this->config['always_upgrade'])
                $this->rehashPasswordRequired = true;
            if ($encoder->isPasswordValid($encoded, $raw, $salt))
                return true;
        }

        return false;
    }

    /**
     * loadEncoders
     */
    private function loadEncoders()
    {
        $encoders = [];
        if (($this->available & 16) && $this->config['sodium'] && class_exists(SodiumPasswordEncoder::class) && SodiumPasswordEncoder::isSupported()) {
            $encoders[] = new SodiumPasswordEncoder($this->config['time_cost'], $this->config['memory_cost']);
        } elseif (($this->available & 16) && ! $this->config['sodium'] && NativePasswordEncoder::isSupported()) {
            $encoders[] = new NativePasswordEncoder($this->config['time_cost'], $this->config['memory_cost'], $this->config['cost']);
        }
        if ($this->available & 8 && BCryptPasswordEncoder::isSupported())
            $encoders[] = new BCryptPasswordEncoder($this->config['cost']);

        if ($this->available & 4)
            $encoders[] = new SHA256PasswordEncoder($this->config['encode_as_base64'], $this->config['iterations_sha256'], $this->config['password_salt_mask'], $this->config['store_salt_separately']);
        if ($this->available & 2)
            $encoders[] = new MD5PasswordEncoder($this->config['iterations_md5']);
        if ($this->available & 1)
            $encoders[] = new PlaintextPasswordEncoder($this->config['ignore_password_case']);
        $this->encoders = $encoders;
    }

    /**
     * @return PasswordEncoderInterface[]
     */
    public function getEncoders(): array
    {
        return $this->encoders;
    }

    /**
     * @var int
     */
    private $available;

    /**
     * definedEncoders
     */
    private function definedEncoders()
    {
        $max = $this->config['maximum_available'];
        $min = $this->allEncoders[$this->config['minimum_available']] <= $this->allEncoders[$this->config['maximum_available']] ? $this->config['minimum_available'] : $this->config['maximum_available'] ;

        $this->available = 0;

        foreach($this->allEncoders as $encoder => $value)
        {
            if ($this->allEncoders[$encoder] <= $this->allEncoders[$max])
                $this->available += $this->allEncoders[$encoder];
            if ($this->allEncoders[$encoder] < $this->allEncoders[$min])
                $this->available -= $this->allEncoders[$encoder];
        }

    }

    /**
     * @return int
     */
    public function getAvailable(): int
    {
        return $this->available;
    }

    /**
     * isRehashPasswordRequired
     * @param $encoded
     * @return bool
     */
    public function isRehashPasswordRequired($encoded): bool
    {
        if (is_null($this->rehashPasswordRequired))
            throw new \InvalidArgumentException('The method "isPasswordValid" must be called before checking "isRehashPasswordRequired"');
        if ($this->rehashPasswordRequired)
            return true;

        if (method_exists($this->getEncoder(), 'isRehashPasswordRequired'))
            return $this->getEncoder()->isRehashPasswordRequired($encoded);

        $encoder = password_get_info($encoded);
        if ($encoder['algo'] > 0)
            return password_needs_rehash($encoded, $encoder['algo'], $this->config);

        return false;
    }
}
