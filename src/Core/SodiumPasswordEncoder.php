<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 16/04/2019
 * Time: 08:05
 */
namespace Crayner\Authenticate\Core;

use Symfony\Component\Security\Core\Encoder\BasePasswordEncoder;
use Symfony\Component\Security\Core\Encoder\SelfSaltingEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\LogicException;

/**
 * Hashes passwords using libsodium.
 *
 * @author Robin Chalas <robin.chalas@gmail.com>
 * @author Zan Baldwin <hello@zanbaldwin.com>
 * @author Dominik Müller <dominik.mueller@jkweb.ch>
 */
class SodiumPasswordEncoder extends BasePasswordEncoder implements SelfSaltingEncoderInterface
{
    /**
     * createEncoder
     * @param int $memoryCost
     * @param int $timeCost
     * @param int $threads
     * @param bool $sodium
     * @param string|null $available
     * @return SelfSaltingEncoderInterface
     */
    public static function createEncoder(int $memoryCost = 65535, int $timeCost = 2, int $threads = 4, bool $sodium = true, ?string $available = 'argon2id'): SelfSaltingEncoderInterface
    {
        if (\class_exists('\Symfony\Component\Security\Core\SodiumPasswordEncoder') && $sodium)
            return new \Symfony\Component\Security\Core\SodiumPasswordEncoder();
        if (self::isSupported() && $sodium)
            return new self();
        if (\defined('PASSWORD_ARGON2ID') && \PHP_VERSION_ID >= 70300 && $available === 'argon2id')
            return new Argon2idPasswordEncoder($memoryCost, $timeCost, $threads);
        if (\defined('PASSWORD_ARGON2I') && \PHP_VERSION_ID >= 70200)
            return new Argon2iPasswordEncoder($memoryCost, $timeCost, $threads);
        throw new \LogicException('Libsodium is not available. You should turn on the Sodium flag in the package, install the sodium extension, upgrade to PHP 7.2+ or use a different encoder.');
    }

    /**
     * isSupported
     * @return bool
     */
    public static function isSupported(): bool
    {
        if (\class_exists('\Symfony\Component\Security\Core\SodiumPasswordEncoder'))
        {
            \trigger_error('The system should not select this class for Symfony 4.3+',E_USER_DEPRECATED);
            return false;
        }
        if (\class_exists('ParagonIE_Sodium_Compat') && \method_exists('ParagonIE_Sodium_Compat', 'crypto_pwhash_is_available')) {
            return \ParagonIE_Sodium_Compat::crypto_pwhash_is_available();
        }
        return \function_exists('sodium_crypto_pwhash_str') || \extension_loaded('libsodium');
    }

    /**
     * encodePassword
     * @param string $raw
     * @param string $salt
     * @return string
     * @throws \SodiumException
     */
    public function encodePassword($raw, $salt)
    {
        if ($this->isPasswordTooLong($raw)) {
            throw new BadCredentialsException('Invalid password.');
        }
        if (\function_exists('sodium_crypto_pwhash_str')) {
            return \sodium_crypto_pwhash_str(
                $raw,
                \SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                \SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            );
        }
        if (\extension_loaded('libsodium')) {
            return \Sodium\crypto_pwhash_str(
                $raw,
                \Sodium\CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                \Sodium\CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            );
        }
        throw new LogicException('Libsodium is not available. You should either install the sodium extension, upgrade to PHP 7.2+ or use a different encoder.');
    }

    /**
     * isPasswordValid
     * @param string $encoded
     * @param string $raw
     * @param string $salt
     * @return bool
     */
    public function isPasswordValid($encoded, $raw, $salt)
    {
        if ($this->isPasswordTooLong($raw)) {
            return false;
        }
        if (\function_exists('sodium_crypto_pwhash_str_verify')) {
            return \sodium_crypto_pwhash_str_verify($encoded, $raw);
        }
        if (\extension_loaded('libsodium')) {
            return \Sodium\crypto_pwhash_str_verify($encoded, $raw);
        }
        throw new LogicException('Libsodium is not available. You should either install the sodium extension, upgrade to PHP 7.2+ or use a different encoder.');
    }
}