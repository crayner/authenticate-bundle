<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 26/03/2019
 * Time: 10:12
 */
namespace Crayner\Authenticate\Core;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Interface UserAuthenticateInterface
 * @package Crayner\Authenticate\Core
 */
interface UserAuthenticateInterface extends UserInterface
{
    /**
     * @param int $failureLimit
     * @return UserAuthenticateInterface
     */
    public function incFailureCount(int $failureLimit): UserAuthenticateInterface;

    /**
     * @return int
     */
    public function getFailureCount(): int;

    /**
     * @return int|null
     */
    public function getLastFailureTime(): ?int;

    /**
     * @return bool
     */
    public function isEnabled(): bool;

    /**
     * @return null|string
     */
    public function getAuthenticateResetToken(): ?string;

    /**
     * @return string|null
     */
    public function getAuthenticateResetTime(): ?int;

    /**
     * @return bool
     */
    public function isValidAuthenticateResetToken(): bool;

    /**
     * The password passed to this method must be encoded.
     *
     * The array is stored as
     *   [strtotime('now')] = $password;
     * so that each password is timestamped.
     *
     * @param string $password
     * @return UserAuthenticateInterface
     */
    public function addPreviousPassword(string $password): UserAuthenticateInterface;

    /**
     * The password passed to this method must be encoded.
     * @param string $password
     * @return UserAuthenticateInterface
     */
    public function removePreviousPassword(string $password): UserAuthenticateInterface;

    /**
     * @return bool
     */
    public function isForcePasswordChange(): bool;
}