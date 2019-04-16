<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
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
            'argon2id',
            'argon2i',
            'bcrypt',
            'sha256',
            'md5',
        ];
        $treeBuilder->getRootNode()
            ->children()
                ->arrayNode('highest_available_encoder')->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('memory_cost')->defaultValue(16384)->end()
                        ->integerNode('time_cost')->defaultValue(2)->end()
                        ->integerNode('threads')->defaultValue(4)->end()
                        ->booleanNode('sodium')->defaultTrue()->end()
                        ->integerNode('cost')->defaultValue(\PASSWORD_BCRYPT_DEFAULT_COST)->min(4)->max(31)->end()
                        ->integerNode('iterations_sha256')->defaultValue(1000)->min(1)->max(32000)->end()
                        ->integerNode('iterations_md5')->defaultValue(1)->min(1)->max(32000)->end()
                        ->booleanNode('encode_as_base64')->defaultFalse()->end()
                        ->scalarNode('password_salt_mask')->defaultValue('{password}{{salt}}')->end()
                        ->enumNode('maximum_available')->values($encoders)->defaultValue('argon2id')->end()
                        ->enumNode('minimum_available')->values($encoders)->defaultValue('md5')->end()
                        ->booleanNode('always_upgrade')->defaultTrue()->end()
                        ->booleanNode('store_salt_separately')->defaultFalse()->end()
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
                        ->arrayNode('error_messages')->addDefaultsIfNotSet()
                            ->children()
                                ->scalarNode('min_length')->defaultValue('Your password needs to be {count} characters long.')->end()
                                ->scalarNode('max_length')->defaultValue('Your password needs to be less than {count} characters long.')->end()
                                ->scalarNode('case_difference')->defaultValue('Your password must contain upper and lower case characters.')->end()
                                ->scalarNode('special_characters')->defaultValue('Your password must contain a special character. !#@$%^&*)(\\][:><?;')->end()
                                ->scalarNode('use_number')->defaultValue('Your password must contain a number.')->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('rotate_password')->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('keep_last_number')->min(0)->max(30)->defaultValue(0)->end()
                        ->integerNode('keep_for_days')->min(0)->max(1500)->defaultValue(0)->end()  // up to four years
                        ->integerNode('change_every')->min(0)->max(365)->defaultValue(0)->end()
                        ->scalarNode('rotate_error_message')->defaultValue('The password has been used before.')->end()
                    ->end()
                ->end()
                ->scalarNode('user_class')->defaultValue('Crayner\Authenticate\Entity\User')->end()
                ->booleanNode('mailer_available')->defaultFalse()->end()
                ->scalarNode('translation_domain')->defaultValue('validators')->end()
                ->arrayNode('messages')->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('current_password_wrong')->defaultValue('Your current password is not valid.')->end()
                        ->scalarNode('no_authenticated_user')->defaultValue('Username/Email could not be found.')->end()
                    ->end()
                ->end()
            ->end()
        ;
        return $treeBuilder;
    }
}
