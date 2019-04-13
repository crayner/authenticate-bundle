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


use Crayner\Authenticate\Core\HighestAvailableEncoder;
use PHPUnit\Framework\TestCase;

class HighestAuthenicatorTest extends TestCase
{
    /**
     * @var string
     */
    CONST PASSWORD = 'tiGGer44';

    /*                ->arrayNode('highest_available_encoder')->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('memory_cost')->defaultValue(16384)->end()
                        ->integerNode('time_cost')->defaultValue(2)->end()
                        ->integerNode('threads')->defaultValue(4)->end()
                        ->integerNode('cost')->defaultValue(\PASSWORD_BCRYPT_DEFAULT_COST)->min(4)->max(31)->end()
                        ->integerNode('iterations_sha256')->defaultValue(1000)->min(1)->max(32000)->end()
                        ->integerNode('iterations_md5')->defaultValue(1)->min(1)->max(32000)->end()
                        ->booleanNode('encode_as_base64')->defaultFalse()->end()
                        ->scalarNode('password_salt_mask')->defaultValue('{password}{{salt}}')->end()
                        ->enumNode('maximum_available')->values($encoders)->defaultValue('argon2i')->end()
                        ->enumNode('minimum_available')->values($encoders)->defaultValue('md5')->end()
                        ->booleanNode('always_upgrade')->defaultTrue()->end()
                    ->end()
*/
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
        $this->assertEquals(md5(HighestAuthenicatorTest::PASSWORD), $encoder->encodePassword(HighestAuthenicatorTest::PASSWORD, null));
        $this->assertTrue($encoder->isPasswordValid(md5(HighestAuthenicatorTest::PASSWORD), HighestAuthenicatorTest::PASSWORD, null));
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
            'iterations_sha256' => 1,
            'iterations_md5' => 1,
            'encode_as_base64' => false,
        ];
        $encoder = new HighestAvailableEncoder();
        $encoder->setConfiguration($config);
        $salt = 'dkfgkjdgfkjdgfkdsgfkj';
        $encoded = hash_pbkdf2('sha256', HighestAuthenicatorTest::PASSWORD, $salt, 1, 40, true);
        $this->assertEquals(bin2hex($encoded), $encoder->encodePassword(HighestAuthenicatorTest::PASSWORD, $salt));
        $this->assertTrue($encoder->isPasswordValid(bin2hex($encoded), HighestAuthenicatorTest::PASSWORD, $salt));

        $config['encode_as_base64'] = true;
        $encoder->setConfiguration($config);
        $this->assertEquals(base64_encode($encoded), $encoder->encodePassword(HighestAuthenicatorTest::PASSWORD, $salt));
        $this->assertTrue($encoder->isPasswordValid(base64_encode($encoded), HighestAuthenicatorTest::PASSWORD, $salt));
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
        ];
        $encoder = new HighestAvailableEncoder();
        $encoder->setConfiguration($config);
        $encoded = password_hash(HighestAuthenicatorTest::PASSWORD, PASSWORD_BCRYPT, ['cost' => 15]);

        $this->assertTrue($encoder->isPasswordValid($encoded, HighestAuthenicatorTest::PASSWORD, null));
    }

    /**
     * testSHA256Encoder
     */
    public function testArgon2iEncoder()
    {
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
        $encoded = password_hash(HighestAuthenicatorTest::PASSWORD, PASSWORD_ARGON2I, $config);

        $this->assertTrue($encoder->isPasswordValid($encoded, HighestAuthenicatorTest::PASSWORD, null));
    }

    /**
     * testSHA256Encoder
     */
    public function testUpgradePassword()
    {
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
            'always_upgrade' => false,
        ];
        $encoder = new HighestAvailableEncoder();
        $encoder->setConfiguration($config);
        $encoded = md5(HighestAuthenicatorTest::PASSWORD);

        $this->assertStringStartsWith('$argon2i$v=19$m=16384,t=2,p=4$', $encoder->encodePassword(HighestAuthenicatorTest::PASSWORD, null));
        $this->assertTrue($encoder->isPasswordValid($encoded, HighestAuthenicatorTest::PASSWORD, null));
        $this->assertEquals($encoded, $encoder->upgradePassword($encoded, HighestAuthenicatorTest::PASSWORD, null));
        $this->assertStringStartsWith('$argon2i$v=19$m=16384,t=2,p=4$', $encoder->upgradePassword($encoded, HighestAuthenicatorTest::PASSWORD, null, true));

        $config['always_upgrade'] = true;
        $encoder->setConfiguration($config);
        $this->assertStringStartsWith('$argon2i$v=19$m=16384,t=2,p=4$', $encoder->upgradePassword($encoded, HighestAuthenicatorTest::PASSWORD, null, true));
    }
}