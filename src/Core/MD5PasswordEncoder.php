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

/**
 * Class MD5PasswordEncoder
 * @package App\Core
 */
class MD5PasswordEncoder extends BasePasswordEncoder
{
    /**
     * @var int
     */
    private $iterations;

    /**
     * MD5PasswordEncoder constructor.
     * @param int $iterations
     */
    public function __construct(int $iterations = 1)
    {
        $this->iterations = $iterations;
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
        for($x=1; $x<$this->iterations; $x++)
            $raw = md5($raw);
        return md5($raw);
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
}
