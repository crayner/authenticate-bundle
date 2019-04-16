<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 14/04/2019
 * Time: 08:05
 */
namespace Crayner\Authenticate\Core;

use Symfony\Component\Security\Core\Encoder\BasePasswordEncoder;
use Symfony\Component\Security\Core\Encoder\SelfSaltingEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Class Argon2idPasswordEncoder
 * @package Crayner\Authenticate\Core
 */
class Argon2idPasswordEncoder extends BasePasswordEncoder implements SelfSaltingEncoderInterface
{
    /**
     * @var array
     */
    private $config = [];

    /**
     * Argon2idPasswordEncoder constructor.
     * @param int|null $memoryCost
     * @param int|null $timeCost
     * @param int|null $threads
     */
    public function __construct(int $memoryCost = null, int $timeCost = null, int $threads = null)
    {
        if (self::isSupported()) {
            $this->setConfig(
                [
                    'memory_cost' => $memoryCost ?? \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
                    'time_cost' => $timeCost ?? \PASSWORD_ARGON2_DEFAULT_TIME_COST,
                    'threads' => $threads ?? \PASSWORD_ARGON2_DEFAULT_THREADS,
                ]
            );
        }
    }

    /**
     * @param array $config
     * @return Argon2iPasswordEncoder
     */
    public function setConfig(array $config): Argon2iPasswordEncoder
    {
        $this->config = $config;
        return $this;
    }

    public static function isSupported()
    {
        return \defined('PASSWORD_ARGON2ID') && \PHP_VERSION_ID >= 70300;
    }

    /**
     * {@inheritdoc}
     */
    public function encodePassword($raw, $salt)
    {
        if ($this->isPasswordTooLong($raw)) {
            throw new BadCredentialsException('Invalid password.');
        }

        if (self::isSupported()) {
            return password_hash($raw, \PASSWORD_ARGON2ID, $this->config);
        }

        throw new \LogicException('Argon2id algorithm is not supported. Please upgrade to PHP 7.3+.');
    }

    /**
     * {@inheritdoc}
     */
    public function isPasswordValid($encoded, $raw, $salt)
    {
        if (self::isSupported()) {
            return !$this->isPasswordTooLong($raw) && password_verify($raw, $encoded);
        }

        throw new \LogicException('Argon2id algorithm is not supported. Please upgrade to PHP 7.3+.');
    }
}
