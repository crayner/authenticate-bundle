<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 26/03/2019
 * Time: 17:29
 */
namespace Crayner\Authenticate\Core;

/**
 * Class AuthenticateManager
 * @package Crayner\Authenticate\Core
 */
class AuthenticateManager
{
    /**
     * @var bool
     */
    private $mailerAvailable;

    /**
     * @return bool
     */
    public function isMailerAvailable(): bool
    {
        return $this->mailerAvailable ? true : false ;
    }

    /**
     * @param bool $mailerAvailable
     * @return AuthenticateManager
     */
    public function setMailerAvailable(bool $mailerAvailable): AuthenticateManager
    {
        $this->mailerAvailable = $mailerAvailable ? true : false ;
        return $this;
    }
}