<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 23/03/2019
 * Time: 15:04
 */
namespace Crayner\Authenticate\DependencyInjection;

use Crayner\Authenticate\Core\Argon2idPasswordEncoder;
use Crayner\Authenticate\Core\Argon2iPasswordEncoder;
use Crayner\Authenticate\Core\AuthenticateManager;
use Crayner\Authenticate\Core\HighestAvailableEncoder;
use Crayner\Authenticate\Core\LoginFormAuthenticator;
use Crayner\Authenticate\Core\Messages;
use Crayner\Authenticate\Core\SecurityUserProvider;
use Crayner\Authenticate\Validator\Password;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

/**
 * Class CraynerAuthenticateExtension
 * @package Crayner\Authenticate\DependencyInjection
 */
class CraynerAuthenticateExtension extends Extension
{
    /**
     * @param array $configs
     * @param ContainerBuilder $container
     * @throws \Exception
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = $this->getConfiguration($configs, $container);
        $config        = $this->processConfiguration($configuration, $configs);

        $locator = new FileLocator(__DIR__ . '/../Resources/config');
        $loader  = new YamlFileLoader(
            $container,
            $locator
        );
        $loader->load('services.yaml');

        if (!empty($config['highest_available_encoder']) && $container->has(HighestAvailableEncoder::class))
            $container
                ->getDefinition(HighestAvailableEncoder::class)
                ->addMethodCall('setConfiguration', [$config['highest_available_encoder']])
            ;

        if ($container->has(HighestAvailableEncoder::class) && $container->has(LoginFormAuthenticator::class))
        {
            $container
                ->getDefinition(LoginFormAuthenticator::class)
                ->addMethodCall('setPasswordEncoder', [$container->getDefinition(HighestAvailableEncoder::class)])
                ->addMethodCall('setFailureConfig', [$config['manage_failures']])
                ->addMethodCall('setUserClass', [$config['user_class']])
                ->addMethodCall('setRotatePassword', [$config['rotate_password']])
            ;
        }

        if ($container->has(Argon2iPasswordEncoder::class) && PHP_VERSION_ID >= 70200)
        {
            $container
                ->getDefinition(Argon2iPasswordEncoder::class)
                ->addMethodCall('setConfig',
                    [
                        'memory_cost' => $config['memory_cost'] ?? \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
                        'time_cost' => $config['time_cost'] ?? \PASSWORD_ARGON2_DEFAULT_TIME_COST,
                        'threads' => $config['threads'] ?? \PASSWORD_ARGON2_DEFAULT_THREADS,
                    ]
                )
            ;
        }

        if ($container->has(Argon2idPasswordEncoder::class) && PHP_VERSION_ID >= 70300)
        {
            $container
                ->getDefinition(Argon2iDPasswordEncoder::class)
                ->addMethodCall('setConfig',
                    [
                        'memory_cost' => $config['memory_cost'] ?? \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
                        'time_cost' => $config['time_cost'] ?? \PASSWORD_ARGON2_DEFAULT_TIME_COST,
                        'threads' => $config['threads'] ?? \PASSWORD_ARGON2_DEFAULT_THREADS,
                    ]
                )
            ;
        }

        if ($container->has(AuthenticateManager::class))
            $container
                ->getDefinition(AuthenticateManager::class)
                ->addMethodCall('setMailerAvailable', [$config['mailer_available']])
            ;

        if ($container->has(Password::class))
            $config['password_validation']['translation_domain'] = $config['translation_domain'];
            $container
                ->getDefinition(Password::class)
                ->addMethodCall('setPasswordValidation', [$config['password_validation']])
            ;

        if ($container->has(SecurityUserProvider::class))
            $config['rotate_password']['translation_domain'] = $config['translation_domain'];
            $container->getDefinition(SecurityUserProvider::class)
                ->addMethodCall('setUserClass', [$config['user_class']])
                ->addMethodCall('setRotatePassword', [$config['rotate_password']])
            ;

        if ($container->has(Messages::class))
            $container->getDefinition(Messages::class)
                ->addMethodCall('setTranslationDomain', [$config['translation_domain']])
                ->addMethodCall('setMessages', [$config['messages']])
                ->addMethodCall('setMessages', [$config['password_validation']['error_messages']])
                ->addMethodCall('setMessages', [['rotate_error_message' => $config['rotate_password']['rotate_error_message']]])
            ;
    }
}
