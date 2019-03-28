<?php
/**
 * Created by PhpStorm.
 *
 * authentication-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 23/03/2019
 * Time: 14:58
 */
namespace Crayner\Authenticate;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Class CraynerAuthenticateBundle
 * @package Crayner\Authenticate
 */
class CraynerAuthenticateBundle extends Bundle
{
    /**
     * @param ContainerBuilder $container
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);
    }

}
