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

use Symfony\Component\Security\Core\Encoder\Argon2iPasswordEncoder;
use Symfony\Component\Security\Core\Encoder\BasePasswordEncoder;
use Symfony\Component\Security\Core\Encoder\BCryptPasswordEncoder;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Class HighestAvailableEncoder
 * @package Crayner\Authenticate\Core
 */
class HighestAvailableEncoder extends BasePasswordEncoder
{
    /**
     * @var array
     */
    private $config = [];

    /**
     * @var string
     */
    private $available;

    /**
     * @var string
     */
    private $currentEncoder;

    /**
     * HighestAvailableEncoder constructor.
     * @param array $options
     */
    public function setConfiguration(
        array $options
    )
    {
        if (strpos($options['password_salt_mask'], '{password}') === false or strpos($options['password_salt_mask'], '{salt}') === false)
            throw new \InvalidArgumentException(sprintf('The %s class requires that the "password_salt_mask" contains both "{password}" and "{salt}".  The current "password_salt_mask" is "%s" and can be changed in the config/packages/crayner_authentication.yaml file.', HighestAvailableEncoder::class, $options['password_salt_mask']));

        $this->config = $options;

        $this->available = null;

        if (\PHP_VERSION_ID >= 70300 && \defined('PASSWORD_ARGON2ID') && $options['maximum_available'] === 'argon2id') {
            $this->available = 'argon2id';
        }

        if (\PHP_VERSION_ID >= 70200 && \defined('PASSWORD_ARGON2I') && in_array($options['maximum_available'], ['argon2id', 'argon2i'])) {
            $this->available = $this->available ?: 'argon2i';
        }

        if (\defined('PASSWORD_BCRYPT') && in_array($options['maximum_available'], ['argon2id', 'argon2i', 'bcrypt'])) {
            $this->available = $this->available ?: 'bcrypt';
        }

        if (empty($this->available) && in_array($options['maximum_available'], ['argon2id', 'argon2i', 'bcrypt', 'sha256'])) {
            $this->available = $this->available ?: 'sha256';
        }

        $this->available = $this->available ?: 'md5';
    }

    /**
     * @return string
     */
    public function getAvailable(): string
    {
        return $this->available =  $this->available ?: 'md5';
    }

    /**
     * Encodes the raw password.
     *
     * @param string $raw  The password to encode
     * @param string $salt The salt
     *
     * @return string The encoded password
     *
     * @throws BadCredentialsException   If the raw password is invalid, e.g. excessively long
     * @throws \InvalidArgumentException If the salt is invalid
     */
    public function encodePassword($raw, $salt)
    {
        $encoder = $this->getMD5Encoder();

        if (! empty($salt) && $this->config['maximum_available'] !== 'md5')
            $encoder = $this->getSHA256Encoder();

        if (\defined('PASSWORD_BCRYPT') && in_array($this->config['maximum_available'], ['argon2i', 'bcrypt']))
            $encoder = $this->getBCryptEncoder();

        if (\PHP_VERSION_ID >= 70200 && \defined('PASSWORD_ARGON2I') && $this->config['maximum_available'] === 'argon2i')
            $encoder = $this->getArgon2iEncoder();

        if (\PHP_VERSION_ID >= 70300 && \defined('PASSWORD_ARGON2ID') && $this->config['maximum_available'] === 'argon2id')
            $encoder = $this->getArgon2iEncoder();

        return $encoder->encodePassword($raw, $salt ?: null);
    }

    /**
     * Checks a raw password against an encoded password.
     *
     * @param string $encoded An encoded password
     * @param string $raw     A raw password
     * @param string $salt    The salt
     *
     * @return bool true if the password is valid, false otherwise
     *
     * @throws \InvalidArgumentException If the salt is invalid
     */
    public function isPasswordValid($encoded, $raw, $salt)
    {
        $valid = false;

        $passwordInfo = password_get_info($encoded);
        if ($passwordInfo['algo'] > 0 || in_array($this->config['minimum_available'], ['bcrypt', 'argon2i', 'argon2id'])) {

            $this->currentEncoder = $passwordInfo['algoName'] !== 'unknown' ? $passwordInfo['algoName'] : $this->config['minimum_available'];
            switch ($this->currentEncoder) {
                case 'argon2id':
                    $encoder = $this->getArgon2idEncoder();
                    break;
                case 'argon2i':
                    $encoder = $this->getArgon2iEncoder();
                    break;
                case 'bcrypt':
                    $encoder = $this->getBCryptEncoder();
                    break;
                default:
                    throw new \InvalidArgumentException(sprintf('Unable to handle %s encryption.', $this->currentEncoder));
            }

            return $encoder->isPasswordValid($encoded, $raw, $salt);
        }

        $this->currentEncoder = 'sha256';
        if (!empty($salt) && $this->config['maximum_available'] !== 'md5') {
            $encoder = $this->getSHA256Encoder();
            $valid = $encoder->isPasswordValid($encoded, $raw, $salt);
            if ($valid)
                return true;
        }

        if ($this->config['minimum_available'] === 'sha256')
            return false;

        $this->currentEncoder = 'md5';
        $encoder = $this->getMD5Encoder();

        return $encoder->isPasswordValid($encoded, $raw, $salt ?: null);
    }

    /**
     * @return string
     */
    public function getCurrentEncoder(): string
    {
        return $this->currentEncoder;
    }

    /**
     * getMD5Encoder
     * @return MD5PasswordEncoder
     */
    private function getMD5Encoder(): MD5PasswordEncoder
    {
        return new MD5PasswordEncoder($this->config['iterations_md5']);
    }

    /**
     * getSHA256Encoder
     * @return SHA256PasswordEncoder
     */
    private function getSHA256Encoder(): SHA256PasswordEncoder
    {
        return new SHA256PasswordEncoder($this->config['encode_as_base64'], $this->config['iterations_sha256'], $this->config['password_salt_mask'], $this->config['store_salt_separately']);
    }

    /**
     * getBCryptEncoder
     * @return BCryptPasswordEncoder
     */
    private function getBCryptEncoder(): BCryptPasswordEncoder
    {
        return new BCryptPasswordEncoder($this->config['cost']);
    }

    /**
     * getArgon2iEncoder
     * @return Argon2iPasswordEncoder
     */
    private function getArgon2iEncoder(): Argon2iPasswordEncoder
    {
        return new Argon2iPasswordEncoder($this->config['memory_cost'], $this->config['time_cost'], $this->config['threads']);
    }

    /**
     * getArgon2idEncoder
     * @return Argon2idPasswordEncoder
     */
    private function getArgon2idEncoder(): Argon2idPasswordEncoder
    {
        return new Argon2idPasswordEncoder($this->config['memory_cost'], $this->config['time_cost'], $this->config['threads']);
    }

    /**
     * @return bool
     */
    private function requiresPasswordUpgrade(): bool
    {
        return $this->currentEncoder !== $this->available && $this->config['always_upgrade'];
    }

    /**
     * @param string $encoded
     * @param string $raw
     * @param string|null $salt
     * @param bool $forceUpgrade
     * @return string
     */
    public function upgradePassword(string $encoded, string $raw, ?string $salt, bool $forceUpgrade = false): string
    {
        if ($this->requiresPasswordUpgrade() || $forceUpgrade)
        {
            $encoded = $this->encodePassword($raw, $salt ?: null);
        }
        return $encoded;
    }
}