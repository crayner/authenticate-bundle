<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 24/04/2019
 * Time: 08:54
 */
namespace Crayner\Authenticate\Core;

use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Encoder\SelfSaltingEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Hashes passwords using password_hash().
 *
 * @author Elnur Abdurrakhimov <elnur@elnur.pro>
 * @author Terje Bråten <terje@braten.be>
 * @author Nicolas Grekas <p@tchwork.com>
 */
final class NativePasswordEncoder implements PasswordEncoderInterface, SelfSaltingEncoderInterface
{
    private const MAX_PASSWORD_LENGTH = 4096;

    private $algo;
    private $options;

    public function __construct(int $opsLimit = null, int $memLimit = null, int $cost = null)
    {
        $cost = $cost ?? 13;
        $opsLimit = $opsLimit ?? max(6, \defined('SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE') ? \SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE : 6);
        $memLimit = $memLimit ?? max(64 * 1024 * 1024, \defined('SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE') ? \SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE : 64 * 1024 * 1024);

        if (2 > $opsLimit) {
            throw new \InvalidArgumentException('$opsLimit must be 2 or greater.');
        }

        if (10 * 1024 > $memLimit) {
            throw new \InvalidArgumentException('$memLimit must be 10k or greater.');
        }

        if ($cost < 4 || 31 < $cost) {
            throw new \InvalidArgumentException('$cost must be in the range of 4-31.');
        }

        $this->algo = \defined('PASSWORD_ARGON2I') ? max(PASSWORD_DEFAULT, \defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_ARGON2I) : PASSWORD_DEFAULT;
        $this->options = [
            'cost' => $cost,
            'time_cost' => $opsLimit,
            'memory_cost' => $memLimit >> 10,
            'threads' => 1,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function encodePassword($raw, $salt)
    {
        if (\strlen($raw) > self::MAX_PASSWORD_LENGTH) {
            throw new BadCredentialsException('Invalid password.');
        }

        // Ignore $salt, the auto-generated one is always the best

        $encoded = password_hash($raw, $this->algo, $this->options);

        if (72 < \strlen($raw) && 0 === strpos($encoded, '$2')) {
            // BCrypt encodes only the first 72 chars
            throw new BadCredentialsException('Invalid password.');
        }

        return $encoded;
    }

    /**
     * {@inheritdoc}
     */
    public function isPasswordValid($encoded, $raw, $salt)
    {
        if (72 < \strlen($raw) && 0 === strpos($encoded, '$2')) {
            // BCrypt encodes only the first 72 chars
            return false;
        }

        return \strlen($raw) <= self::MAX_PASSWORD_LENGTH && password_verify($raw, $encoded);
    }

    /**
     * isSupported
     * @return bool
     */
    public static function isSupported()
    {
        return \PHP_VERSION_ID >= 50500 && \defined('PASSWORD_BCRYPT');
    }

    /**
     * isRehashPasswordRequired
     *
     * Checks if the password being tested is actually at the best possible encryption.
     *
     * @param string $encoded
     * @return bool
     */
    public function isRehashPasswordRequired(string $encoded): bool
    {
        $encoder = password_get_info($encoded);
        if ($encoder['algo'] === $this->algo)
            return password_needs_rehash($encoded, $this->algo, $this->options);

        return true;
    }
}
