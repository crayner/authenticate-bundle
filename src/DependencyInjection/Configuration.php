<?php
/**
 * Created by PhpStorm.
 *
 * authentication-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 23/03/2019
 * Time: 15:45
 */
namespace Crayner\Authenticate\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Class Configuration
 * @package Crayner\Authenticate\DependencyInjection
 */
class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder('crayner_authenticate');
        $encoders = [
            'argon2i',
            'bcrypt',
            'sha256',
            'md5',
        ];
        $treeBuilder->getRootNode()
            ->children()
                ->arrayNode('highest_available_encoder')->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('memory_cost')->defaultValue(\PASSWORD_ARGON2_DEFAULT_MEMORY_COST)->end()
                        ->integerNode('time_cost')->defaultValue(\PASSWORD_ARGON2_DEFAULT_TIME_COST)->end()
                        ->integerNode('threads')->defaultValue(\PASSWORD_ARGON2_DEFAULT_THREADS)->end()
                        ->integerNode('cost')->defaultValue(\PASSWORD_BCRYPT_DEFAULT_COST)->min(4)->max(31)->end()
                        ->integerNode('iterations_sha256')->defaultValue(1000)->min(1)->max(32000)->end()
                        ->integerNode('iterations_md5')->defaultValue(1)->min(1)->max(32000)->end()
                        ->booleanNode('encode_as_base64')->defaultFalse()->end()
                        ->scalarNode('password_salt_mask')->defaultValue('{password}{{salt}}')->end()
                        ->enumNode('maximum_available')->values($encoders)->defaultValue('argon2i')->end()
                        ->enumNode('minimum_available')->values($encoders)->defaultValue('md5')->end()
                        ->booleanNode('always_upgrade')->defaultTrue()->end()
                    ->end()
                ->end()
                ->arrayNode('manage_failures')->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('count')->min(0)->max(9)->defaultValue(3)->end()
                        ->integerNode('wait_time')->min(0)->max(60)->defaultValue(20)->end()
                        ->booleanNode('session')->defaultTrue()->end()
                        ->booleanNode('user')->defaultTrue()->end()
                    ->end()
                ->end()
                ->arrayNode('password_validation')->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('min_length')->min(0)->max(150)->defaultValue(8)->end()
                        ->integerNode('max_length')->min(0)->max(150)->defaultValue(150)->end()
                        ->booleanNode('case_difference')->defaultTrue()->end()
                        ->booleanNode('special_characters')->defaultTrue()->end()
                        ->booleanNode('use_number')->defaultTrue()->end()
                        ->scalarNode('translation_domain')->defaultValue('validators')->end()
                        ->arrayNode('error_messages')->addDefaultsIfNotSet()
                            ->children()
                                ->scalarNode('min_length')->defaultValue('Your password needs to be %d characters long.')->end()
                                ->scalarNode('max_length')->defaultValue('Your password needs to be less than %d characters long.')->end()
                                ->scalarNode('case_difference')->defaultValue('Your password must contain upper and lower case characters.')->end()
                                ->scalarNode('special_characters')->defaultValue('Your password must contain a special character. %s')->end()
                                ->scalarNode('use_number')->defaultValue('Your password must contain a number')->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
                ->scalarNode('user_class')->isRequired()->end()
                ->booleanNode('mailer_available')->defaultFalse()->end()
            ->end()
        ;
        return $treeBuilder;
    }
}
