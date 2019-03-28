<?php
/**
 * Created by PhpStorm.
 *
 * authentication-bundle
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
use Crayner\Authenticate\Validator\Password;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

/**
 * Class CraynerAuthenticateExtension
 * @package Crayner\Core\DependencyInjection
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
/*
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
*/
    }
}
