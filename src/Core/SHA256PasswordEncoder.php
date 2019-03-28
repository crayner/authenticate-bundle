<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 23/11/2018
 * Time: 15:27
 */
namespace Crayner\Authenticate\Core;

use Symfony\Component\Security\Core\Encoder\BasePasswordEncoder;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Class SHA256PasswordEncoder
 * @package Crayner\Authenticate\Core
 */
class SHA256PasswordEncoder extends BasePasswordEncoder
{
    /**
     * @var int
     */
    private $iterations = 6;

    /**
     * @var string
     */
    private $passwordSaltMask = '{password}{{salt}}';

    /**
     * @var boolean
     */
    private $encodeHashAsBase64 = false;

    /**
     * @var int
     */
    private $length = 40;

    /**
     * SHA256PasswordEncoder constructor.
     * @param int|null $loops
     * @param string|null $passwordSaltMask
     */
    public function __construct(bool $encodeHashAsBase64 = false, int $iterations = 1000, ?string $passwordSaltMask = '{password}{{salt}}')
    {
        if ($iterations < 1 || $iterations > 10000)
            throw new \InvalidArgumentException('SHA256 Loops must be in the range of 1-10000.');
        $this->iterations = $iterations;
        $this->passwordSaltMask = $passwordSaltMask;
        $this->encodeHashAsBase64 = $encodeHashAsBase64;
    }

    /**
     * Encodes the raw password.
     *
     * @param string $raw  The password to encode
     * @param string $salt The salt
     *
     * @return string The encoded password
     */
    public function encodePassword($raw, $salt): string
    {
        if ($this->isPasswordTooLong($raw)) {
            throw new BadCredentialsException('Invalid password.');
        }

        $digest = hash_pbkdf2('sha256', $raw, $salt, $this->iterations, 40, true);

        return $this->encodeHashAsBase64 ? base64_encode($digest) : bin2hex($digest);
    }

    /**
     * Checks a raw password against an encoded password.
     *
     * @param string $encoded An encoded password
     * @param string $raw     A raw password
     * @param string $salt    The salt
     *
     * @return bool true if the password is valid, false otherwise
     */
    public function isPasswordValid($encoded, $raw, $salt): bool
    {
        if ($encoded === $this->encodePassword($raw, $salt))
            return true;
        return false;
    }

    /**
     * Merges a password and a salt.
     *
     * @param string $password The password to be used
     * @param string $salt     The salt to be used
     *
     * @return string a merged password and salt
     *
     * @throws \InvalidArgumentException
     */
    protected function mergePasswordAndSalt($password, $salt): string
    {
        if (empty($salt)) {
            return $password;
        }

        if (false !== strrpos($salt, '{') || false !== strrpos($salt, '}')) {
            throw new \InvalidArgumentException('Cannot use { or } in salt.');
        }


        return str_replace(['{password}', '{salt}'], [$password,$salt], $this->passwordSaltMask);
    }
}
