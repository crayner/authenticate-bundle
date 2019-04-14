<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 13/04/2019
 * Time: 15:30
 */
namespace Crayner\Authenticate\Tests;

use Crayner\Authenticate\Core\Argon2idPasswordEncoder;
use Crayner\Authenticate\Core\HighestAvailableEncoder;
use Crayner\Authenticate\Core\MD5PasswordEncoder;
use Crayner\Authenticate\Core\SHA256PasswordEncoder;
use PHPUnit\Framework\TestCase;

/**
 * Class HighestAuthenticatorTest
 * @package Crayner\Authenticate\Tests
 */
class HighestAuthenticatorTest extends TestCase
{
    /**
     * @var string
     */
    CONST PASSWORD = 'tiGGer44';

    /**
     * testMD5Encoder
     */
    public function testMD5Encoder()
    {
        $config = [
            'maximum_available' => 'md5',
            'minimum_available' => 'md5',
            'password_salt_mask' => '{password}{{salt}}',
            'iterations_md5' => 1,
        ];
        $encoder = new HighestAvailableEncoder();
        $encoder->setConfiguration($config);
        $this->assertEquals('md5', $encoder->getAvailable());
        $encoded = md5(HighestAuthenticatorTest::PASSWORD);
        $this->assertEquals($encoded, $encoder->encodePassword(HighestAuthenticatorTest::PASSWORD, null));
        $this->assertTrue($encoder->isPasswordValid($encoded, HighestAuthenticatorTest::PASSWORD, null));

        $md5 = new MD5PasswordEncoder(1);
        $this->assertEquals($encoded, $md5->encodePassword(HighestAuthenticatorTest::PASSWORD, null));
        $this->assertTrue($md5->isPasswordValid($encoded, HighestAuthenticatorTest::PASSWORD, null));
    }

    /**
     * testSHA256Encoder
     */
    public function testSHA256Encoder()
    {
        $config = [
            'maximum_available' => 'sha256',
            'minimum_available' => 'md5',
            'password_salt_mask' => '{password}{{salt}}',
            'store_salt_separately' => true,
            'iterations_sha256' => 1,
            'iterations_md5' => 1,
            'encode_as_base64' => false,
        ];
        $encoder = new HighestAvailableEncoder();
        $encoder->setConfiguration($config);
        $this->assertEquals('sha256', $encoder->getAvailable());
        $salt = 'dkfgkjdgfkjdgfkdsgfkj';
        $encoded = hash_pbkdf2('sha256', HighestAuthenticatorTest::PASSWORD, $salt, 1, 40, true);
        $this->assertEquals(bin2hex($encoded), $encoder->encodePassword(HighestAuthenticatorTest::PASSWORD, $salt));
        $this->assertTrue($encoder->isPasswordValid(bin2hex($encoded), HighestAuthenticatorTest::PASSWORD, $salt));

        $config['encode_as_base64'] = true;
        $encoder->setConfiguration($config);
        $this->assertEquals(base64_encode($encoded), $encoder->encodePassword(HighestAuthenticatorTest::PASSWORD, $salt));
        $this->assertTrue($encoder->isPasswordValid(base64_encode($encoded), HighestAuthenticatorTest::PASSWORD, $salt));

        $sha256 = new SHA256PasswordEncoder(false, 1, '{password}{{salt}}', true);
        $this->assertTrue($sha256->isPasswordValid(bin2hex($encoded), HighestAuthenticatorTest::PASSWORD, $salt), 'Base64 = false, Store Salt Separately = true');
        $sha256 = new SHA256PasswordEncoder(true, 1, '{password}{{salt}}', true);
        $this->assertTrue($sha256->isPasswordValid(base64_encode($encoded), HighestAuthenticatorTest::PASSWORD, $salt), 'Base64 = true, Store Salt Separately = true');

        $sha256 = new SHA256PasswordEncoder(false, 1, '{password}{{salt}}', false);
        $this->assertTrue($sha256->isPasswordValid(bin2hex($encoded).'{'.$salt.'}', HighestAuthenticatorTest::PASSWORD, $salt), 'Base64 = false, Store Salt Separately = false');
        $sha256 = new SHA256PasswordEncoder(true, 1, '{password}{{salt}}', false);
        $this->assertTrue($sha256->isPasswordValid(base64_encode($encoded.'{'.$salt.'}'), HighestAuthenticatorTest::PASSWORD, $salt), 'Base64 = true, Store Salt Separately = false');

    }

    /**
     * testSHA256Encoder
     */
    public function testBCryptEncoder()
    {
        $config = [
            'maximum_available' => 'bcrypt',
            'minimum_available' => 'md5',
            'password_salt_mask' => '{password}{{salt}}',
            'iterations_sha256' => 1,
            'iterations_md5' => 1,
            'encode_as_base64' => false,
            'cost' => 15,
            'memory_cost' => 16384,
            'time_cost' => 2,
            'threads' => 4,
            'always_upgrade' => false,
        ];
        $encoder = new HighestAvailableEncoder();
        $encoder->setConfiguration($config);
        $this->assertEquals('bcrypt', $encoder->getAvailable());
        $encoded = password_hash(HighestAuthenticatorTest::PASSWORD, PASSWORD_BCRYPT, ['cost' => 15]);

        $this->assertTrue($encoder->isPasswordValid($encoded, HighestAuthenticatorTest::PASSWORD, null));
    }

    /**
     * testSHA256Encoder
     */
    public function testArgon2iEncoder()
    {
        if (\PHP_VERSION_ID >= 70200) {
            $config = [
                'maximum_available' => 'argon2i',
                'minimum_available' => 'md5',
                'password_salt_mask' => '{password}{{salt}}',
                'iterations_sha256' => 1,
                'iterations_md5' => 1,
                'encode_as_base64' => false,
                'cost' => 15,
                'memory_cost' => 16384,
                'time_cost' => 2,
                'threads' => 4,
            ];
            $encoder = new HighestAvailableEncoder();
            $encoder->setConfiguration($config);
            $this->assertEquals('argon2i', $encoder->getAvailable());
            $encoded = password_hash(HighestAuthenticatorTest::PASSWORD, PASSWORD_ARGON2I, $config);

            $this->assertTrue($encoder->isPasswordValid($encoded, HighestAuthenticatorTest::PASSWORD, null));
            $this->assertEquals('argon2i', $encoder->getCurrentEncoder(), 'Encoder Name');
        } else
            $this->assertFalse(\PHP_VERSION_ID >= 70200);
    }

    /**
     * testSHA256Encoder
     */
    public function testArgon2idEncoder()
    {
        if (\PHP_VERSION_ID >= 70300) {
            $config = [
                'maximum_available' => 'argon2id',
                'minimum_available' => 'md5',
                'password_salt_mask' => '{password}{{salt}}',
                'iterations_sha256' => 1,
                'iterations_md5' => 1,
                'encode_as_base64' => false,
                'cost' => 15,
                'memory_cost' => 16384,
                'time_cost' => 2,
                'threads' => 4,
            ];
            $encoder = new HighestAvailableEncoder();
            $encoder->setConfiguration($config);
            $this->assertEquals('argon2id', $encoder->getAvailable());
            $encoded = password_hash(HighestAuthenticatorTest::PASSWORD, PASSWORD_ARGON2ID, $config);

            $this->assertStringStartsWith('$argon2id$v=19$m=16384,t=2,p=4$', $encoded);

            $this->assertTrue($encoder->isPasswordValid($encoded, HighestAuthenticatorTest::PASSWORD, null));
            $this->assertEquals('argon2id', $encoder->getCurrentEncoder());

            $argon2id = new Argon2idPasswordEncoder(16384, 2, 4);
            $this->assertTrue($argon2id->isPasswordValid($encoded, HighestAuthenticatorTest::PASSWORD, null));
            $this->assertTrue($argon2id::isSupported());
            $this->assertStringStartsWith('$argon2id$v=19$m=16384,t=2,p=4$', $argon2id->encodePassword(HighestAuthenticatorTest::PASSWORD, null));
        } else
            $this->assertFalse(\PHP_VERSION_ID >= 70300);
    }

    /**
     * testSHA256Encoder
     */
    public function testUpgradePassword()
    {
        $config = [
            'maximum_available' => 'argon2id',
            'minimum_available' => 'md5',
            'password_salt_mask' => '{password}{{salt}}',
            'iterations_sha256' => 1,
            'iterations_md5' => 1,
            'encode_as_base64' => false,
            'cost' => 15,
            'memory_cost' => 16384,
            'time_cost' => 2,
            'threads' => 4,
            'always_upgrade' => false,
        ];
        $encoder = new HighestAvailableEncoder();
        $encoder->setConfiguration($config);
        $encoded = md5(HighestAuthenticatorTest::PASSWORD);

        $this->assertStringStartsWith('$argon2i$v=19$m=16384,t=2,p=4$', $encoder->encodePassword(HighestAuthenticatorTest::PASSWORD, null));
        $this->assertTrue($encoder->isPasswordValid($encoded, HighestAuthenticatorTest::PASSWORD, null));
        $this->assertEquals($encoded, $encoder->upgradePassword($encoded, HighestAuthenticatorTest::PASSWORD, null));
        $this->assertStringStartsWith('$argon2i$v=19$m=16384,t=2,p=4$', $encoder->upgradePassword($encoded, HighestAuthenticatorTest::PASSWORD, null, true));

        $config['always_upgrade'] = true;
        $encoder->setConfiguration($config);
        $this->assertStringStartsWith('$argon2i$v=19$m=16384,t=2,p=4$', $encoder->upgradePassword($encoded, HighestAuthenticatorTest::PASSWORD, null, true));
    }

    public function testMinimumEncoder()
    {
        $config = [
            'maximum_available' => 'bcrypt',
            'minimum_available' => 'bcrypt',
            'password_salt_mask' => '{password}{{salt}}',
            'iterations_sha256' => 1,
            'iterations_md5' => 1,
            'encode_as_base64' => false,
            'cost' => 15,
            'memory_cost' => 16384,
            'time_cost' => 2,
            'threads' => 4,
            'always_upgrade' => false,
        ];

        $encoder = new HighestAvailableEncoder();
        $encoder->setConfiguration($config);
        $encoded = md5(HighestAuthenticatorTest::PASSWORD);

        $this->assertFalse($encoder->isPasswordValid($encoded, HighestAuthenticatorTest::PASSWORD, null));
        $this->assertStringStartsWith('$2y$15$', $encoder->encodePassword(HighestAuthenticatorTest::PASSWORD, null));
    }
}