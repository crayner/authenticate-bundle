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

use Crayner\Authenticate\Core\BCryptPasswordEncoder;
use Crayner\Authenticate\Core\HighestAvailablePasswordEncoder;
use Crayner\Authenticate\Core\MD5PasswordEncoder;
use Crayner\Authenticate\Core\NativePasswordEncoder;
use Crayner\Authenticate\Core\SHA256PasswordEncoder;
use Crayner\Authenticate\Core\SodiumPasswordEncoder;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Core\Encoder\PlaintextPasswordEncoder;
use Symfony\Component\Security\Core\Encoder\SelfSaltingEncoderInterface;

/**
 * Class HighestAvailablePasswordEncoderTest
 * @package Crayner\Authenticate\Tests
 */
class HighestAvailablePasswordEncoderTest extends WebTestCase
{
    /**
     * @var string
     */
    CONST PASSWORD = 'tiGGer44';

    /**
     * testMD5Encoder
     */
    public function testPlaintextEncoder()
    {
        $config = [
            'maximum_available' => 'plain',
            'minimum_available' => 'plain',
            'ignore_password_case' => false,
        ];
        $encoder = new HighestAvailablePasswordEncoder();
        $encoder->setConfiguration($config);
        $this->assertEquals(1, $encoder->getAvailable());
        $encoded = HighestAvailablePasswordEncoderTest::PASSWORD;
        $this->assertEquals($encoded, $encoder->encodePassword(HighestAvailablePasswordEncoderTest::PASSWORD, null));
        $this->assertTrue($encoder->isPasswordValid($encoded, HighestAvailablePasswordEncoderTest::PASSWORD, null));
        $this->assertEquals(PlaintextPasswordEncoder::class, get_class($encoder->getEncoder()));
    }

    /**
     * testMD5Encoder
     */
    public function testMD5Encoder()
    {
        $config = [
            'maximum_available' => 'md5',
            'minimum_available' => 'md5',
            'iterations_md5' => 1,
        ];
        $encoder = new HighestAvailablePasswordEncoder();
        $encoder->setConfiguration($config);
        $this->assertEquals(2, $encoder->getAvailable());
        $encoded = md5(HighestAvailablePasswordEncoderTest::PASSWORD);
        $this->assertEquals($encoded, $encoder->encodePassword(HighestAvailablePasswordEncoderTest::PASSWORD, null));
        $this->assertTrue($encoder->isPasswordValid($encoded, HighestAvailablePasswordEncoderTest::PASSWORD, null));
        $this->assertEquals(MD5PasswordEncoder::class, get_class($encoder->getEncoder()));

        $md5 = new MD5PasswordEncoder(1);
        $this->assertEquals($encoded, $md5->encodePassword(HighestAvailablePasswordEncoderTest::PASSWORD, null));
        $this->assertTrue($md5->isPasswordValid($encoded, HighestAvailablePasswordEncoderTest::PASSWORD, null));
    }

    /**
     * testSHA256Encoder
     */
    public function testSHA256Encoder()
    {
        $config = [
            'maximum_available' => 'sha256',
            'minimum_available' => 'sha256',
            'password_salt_mask' => '{password}{{salt}}',
            'store_salt_separately' => true,
            'iterations_sha256' => 1,
            'encode_as_base64' => false,
        ];
        $encoder = new HighestAvailablePasswordEncoder();
        $encoder->setConfiguration($config);
        $this->assertEquals(4, $encoder->getAvailable());
        $salt = uniqid('', true);
        $encoded = hash_pbkdf2('sha256', HighestAvailablePasswordEncoderTest::PASSWORD, $salt, 1, 40, true);
        $this->assertEquals(bin2hex($encoded), $encoder->encodePassword(HighestAvailablePasswordEncoderTest::PASSWORD, $salt));
        $this->assertTrue($encoder->isPasswordValid(bin2hex($encoded), HighestAvailablePasswordEncoderTest::PASSWORD, $salt));
        $this->assertEquals(SHA256PasswordEncoder::class, get_class($encoder->getEncoder()));

        $config['encode_as_base64'] = true;
        $encoder->setConfiguration($config);
        $this->assertEquals(base64_encode($encoded), $encoder->encodePassword(HighestAvailablePasswordEncoderTest::PASSWORD, $salt));
        $this->assertTrue($encoder->isPasswordValid(base64_encode($encoded), HighestAvailablePasswordEncoderTest::PASSWORD, $salt));

        $sha256 = new SHA256PasswordEncoder(false, 1, '{password}{{salt}}', true);
        $this->assertTrue($sha256->isPasswordValid(bin2hex($encoded), HighestAvailablePasswordEncoderTest::PASSWORD, $salt), 'Base64 = false, Store Salt Separately = true');
        $sha256 = new SHA256PasswordEncoder(true, 1, '{password}{{salt}}', true);
        $this->assertTrue($sha256->isPasswordValid(base64_encode($encoded), HighestAvailablePasswordEncoderTest::PASSWORD, $salt), 'Base64 = true, Store Salt Separately = true');

        $sha256 = new SHA256PasswordEncoder(false, 1, '{password}{{salt}}', false);
        $this->assertTrue($sha256->isPasswordValid(bin2hex($encoded).'{'.$salt.'}', HighestAvailablePasswordEncoderTest::PASSWORD, $salt), 'Base64 = false, Store Salt Separately = false');
        $sha256 = new SHA256PasswordEncoder(true, 1, '{password}{{salt}}', false);
        $this->assertTrue($sha256->isPasswordValid(base64_encode($encoded.'{'.$salt.'}'), HighestAvailablePasswordEncoderTest::PASSWORD, $salt), 'Base64 = true, Store Salt Separately = false');

    }

    /**
     * testBCryptEncoder
     */
    public function testBCryptEncoder()
    {
        $config = [
            'maximum_available' => 'bcrypt',
            'minimum_available' => 'bcrypt',
            'cost' => 10,
        ];
        $encoder = new HighestAvailablePasswordEncoder();
        $encoder->setConfiguration($config);
        $this->assertEquals(8, $encoder->getAvailable());
        $encoded = password_hash(HighestAvailablePasswordEncoderTest::PASSWORD, PASSWORD_BCRYPT, ['cost' => 15]);

        $this->assertTrue($encoder->isPasswordValid($encoded, HighestAvailablePasswordEncoderTest::PASSWORD, null));
        $this->assertEquals(BCryptPasswordEncoder::class, get_class($encoder->getEncoder()));
    }

    /**
     * testArgon2iEncoder
     */
    public function testNativeEncoder()
    {
        if (NativePasswordEncoder::isSupported()) {
            $config = [
                'maximum_available' => 'argon2',
                'minimum_available' => 'argon2',
                'password_salt_mask' => '{password}{{salt}}',
                'memory_cost' => 16384,
                'time_cost' => 2,
                'threads' => 4,
                'sodium' => false,
                'cost' => 10,
            ];
            $encoder = new HighestAvailablePasswordEncoder();
            $encoder->setConfiguration($config);
            $this->assertEquals(16, $encoder->getAvailable());


            $encoded = password_hash(HighestAvailablePasswordEncoderTest::PASSWORD, PASSWORD_BCRYPT, $config);

            $this->assertTrue($encoder->isPasswordValid($encoded, HighestAvailablePasswordEncoderTest::PASSWORD, null));
            $this->assertEquals(NativePasswordEncoder::class, get_class($encoder->getEncoder()));
            $this->assertTrue($encoder->isRehashPasswordRequired($encoded));


        } else
            $this->assertFalse(false);
    }

    /**
     * testSodiumEncoder
     */
    public function testSodiumEncoder()
    {
        if (SodiumPasswordEncoder::isSupported()) {
            $config = [
                'maximum_available' => 'argon2',
                'minimum_available' => 'argon2',
                'cost' => 10,
                'memory_cost' => 65535,
                'time_cost' => 2,
                'threads' => 1,
                'sodium' => true,
                'always_upgrade' => false,
            ];
            $encoder = new HighestAvailablePasswordEncoder();
            $encoder->setConfiguration($config);
            $this->assertEquals(SodiumPasswordEncoder::class, get_class($encoder->getEncoder()));
            $encoded = password_hash(HighestAvailablePasswordEncoderTest::PASSWORD, 2, $config);
            $this->assertTrue($encoder->isPasswordValid($encoded, HighestAvailablePasswordEncoderTest::PASSWORD, null), 'Password is not valid.');
            $this->assertStringStartsWith('$argon2id$v=19$m=63,t=2,p=1$', $encoder->encodePassword(HighestAvailablePasswordEncoderTest::PASSWORD, null));
            $this->assertTrue($encoder->isRehashPasswordRequired($encoded),'Sodium Password not needs rehash.');


        } else
            $this->assertFalse(false);
    }

    /**
     * testSHA256Encoder
     */
    public function testRehashPassword()
    {
        $config = [
            'maximum_available' => 'argon2',
            'minimum_available' => 'plain',
            'password_salt_mask' => '{password}{{salt}}',
            'iterations_sha256' => 1,
            'iterations_md5' => 1,
            'encode_as_base64' => false,
            'cost' => 10,
            'memory_cost' => 65535,
            'time_cost' => 2,
            'threads' => 4,
            'sodium' => true,
            'always_upgrade' => false,
            'store_salt_separately' => false,
            'ignore_password_case' => false,
        ];
        $encoder = new HighestAvailablePasswordEncoder();
        $encoder->setConfiguration($config);
        $encoded = HighestAvailablePasswordEncoderTest::PASSWORD;

        $prefix = '$argon2id$v=19$m=63,t=2,p=1$';

        $this->assertTrue($encoder->isPasswordValid($encoded, HighestAvailablePasswordEncoderTest::PASSWORD, null));
        $this->assertTrue($encoder->isRehashPasswordRequired($encoded), 'No Rehash Required.');
        $this->assertStringStartsWith($prefix, $encoder->encodePassword( HighestAvailablePasswordEncoderTest::PASSWORD, null));

        $config['always_upgrade'] = true;
        $encoder->setConfiguration($config);
        $this->assertTrue($encoder->isPasswordValid($encoded, HighestAvailablePasswordEncoderTest::PASSWORD, null),'Password is not valid');
        $this->assertTrue($encoder->isRehashPasswordRequired($encoded), 'Rehash Required.');
        $this->assertStringStartsWith($prefix, $encoder->encodePassword(HighestAvailablePasswordEncoderTest::PASSWORD, null), 'Password should upgrade');
        $this->assertEquals(SodiumPasswordEncoder::class, get_class($encoder->getEncoder()));

        //Assert all the encoders.
        $encoders = [];
        foreach($encoder->getEncoders() as $item)
            $encoders[] = get_class($item);
        $this->assertTrue(in_array(PlaintextPasswordEncoder::class, $encoders), PlaintextPasswordEncoder::class);
        $this->assertTrue(in_array(MD5PasswordEncoder::class, $encoders), MD5PasswordEncoder::class);
        $this->assertTrue(in_array(SHA256PasswordEncoder::class, $encoders), SHA256PasswordEncoder::class);
        $this->assertTrue(in_array(BCryptPasswordEncoder::class, $encoders), BCryptPasswordEncoder::class);
        $this->assertTrue(in_array(SodiumPasswordEncoder::class, $encoders), SodiumPasswordEncoder::class);

        $config['sodium'] = false;
        $encoder->setConfiguration($config);
        $encoders = [];
        foreach($encoder->getEncoders() as $item)
            $encoders[] = get_class($item);
        $this->assertTrue(in_array(PlaintextPasswordEncoder::class, $encoders), PlaintextPasswordEncoder::class);
        $this->assertTrue(in_array(MD5PasswordEncoder::class, $encoders), MD5PasswordEncoder::class);
        $this->assertTrue(in_array(SHA256PasswordEncoder::class, $encoders), SHA256PasswordEncoder::class);
        $this->assertTrue(in_array(BCryptPasswordEncoder::class, $encoders), BCryptPasswordEncoder::class);
        $this->assertTrue(in_array(NativePasswordEncoder::class, $encoders), NativePasswordEncoder::class);

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
            'cost' => 10,
            'memory_cost' => 16384,
            'time_cost' => 2,
            'threads' => 4,
            'always_upgrade' => false,
        ];

        $encoder = new HighestAvailablePasswordEncoder();
        $encoder->setConfiguration($config);
        $encoded = md5(HighestAvailablePasswordEncoderTest::PASSWORD);

        $this->assertFalse($encoder->isPasswordValid($encoded, HighestAvailablePasswordEncoderTest::PASSWORD, null));
        $this->assertStringStartsWith('$2y$10$', $encoder->encodePassword(HighestAvailablePasswordEncoderTest::PASSWORD, null));
        $this->assertEquals(BCryptPasswordEncoder::class, get_class($encoder->getEncoder()));
    }
}