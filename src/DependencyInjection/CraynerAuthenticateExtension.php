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

use Crayner\Authenticate\Core\AuthenticateManager;
use Crayner\Authenticate\Core\HighestAvailableEncoder;
use Crayner\Authenticate\Core\LoginFormAuthenticator;
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

        if ($container->has(AuthenticateManager::class))
            $container
                ->getDefinition(AuthenticateManager::class)
                ->addMethodCall('setMailerAvailable', [$config['mailer_available']])
            ;

        if ($container->has(Password::class))
            $container
                ->getDefinition(Password::class)
                ->addMethodCall('setPasswordValidation', [$config['password_validation']])
            ;

        if ($container->has(SecurityUserProvider::class))
            $container->getDefinition(SecurityUserProvider::class)
                ->addMethodCall('setUserClass', [$config['user_class']])
                ->addMethodCall('setRotatePassword', [$config['rotate_password']])
            ;

        if (! $container->hasParameter('security.heirarchy.roles'))
            $container->setParameter('security.heirarchy.roles',
                [
                    'ROLE_USER' => null,
                    'ROLE_ALLOWED_TO_SWITCH' => null,
                    'ROLE_SYSTEM_ADMIN' => [
                        'ROLE_USER' => null,
                    ],
                ]
            );
    }
}
