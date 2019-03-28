<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 26/03/2019
 * Time: 14:19
 */
namespace Crayner\Authenticate\Entity;

use Crayner\Authenticate\Core\UserAuthenticateInterface;

/**
 * Trait UserAuthenticationTrait
 * @package Crayner\Authenticate\Entity
 */
trait UserAuthenticationTrait
{
    /**
     * @var integer
     */
    private $failureCount;

    /**
     * @param int $failureLimit
     * @return UserAuthenticateInterface
     */
    public function incFailureCount(int $failureLimit): UserAuthenticateInterface
    {
        $this->setFailureCount($this->getFailureCount() + 1);
        if ($this->failureCount >= $failureLimit)
            return $this;
        return $this->setLastFailureTime(strtotime('now'));
    }

    /**
     * @return int
     */
    public function getFailureCount(): int
    {
        return $this->failureCount ?: 0;
    }

    /**
     * @param int $failureCount
     * @return UserAuthenticateInterface
     */
    public function setFailureCount(int $failureCount): UserAuthenticateInterface
    {
        $this->failureCount = $failureCount ?: 0;
        if (empty($this->failureCount))
            $this->setLastFailureTime(null);
        return $this;
    }

    /**
     * @var integer|null
     */
    private $lastFailureTime;

    /**
     * @return int|null
     */
    public function getLastFailureTime(): ?int
    {
        return $this->lastFailureTime;
    }

    /**
     * @param int|null $lastFailureTime
     * @return UserAuthenticateInterface
     */
    public function setLastFailureTime(?int $lastFailureTime): UserAuthenticateInterface
    {
        $this->lastFailureTime = $lastFailureTime;
        return $this;
    }

    /**
     * @var bool
     */
    private $enabled;

    /**
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->enabled ? true : false ;
    }

    /**
     * @param bool|null $enabled
     * @return UserAuthenticateInterface
     */
    public function setEnabled(?bool $enabled): UserAuthenticateInterface
    {
        $this->enabled = $enabled ? true : false;
        return $this;
    }

    /**
     * @var \DateTimeImmutable
     */
    private $lastAuthenticateTime;

    /**
     * @return \DateTimeImmutable
     */
    public function getLastAuthenticateTime(): \DateTimeImmutable
    {
        return $this->lastAuthenticateTime;
    }

    /**
     * @param \DateTimeImmutable $lastAuthenticateTime
     * @return UserAuthenticateInterface
     */
    public function setLastAuthenticateTime(\DateTimeImmutable $lastAuthenticateTime): UserAuthenticateInterface
    {
        $this->lastAuthenticateTime = $lastAuthenticateTime;
        return $this;
    }

    /**
     * @var null|string
     */
    private $authenticateResetToken;

    /**
     * @return string|null
     */
    public function getAuthenticateResetToken(): ?string
    {
        return $this->authenticateResetToken;
    }

    /**
     * @return string|null
     */
    public function getAuthenticateResetTime(): ?int
    {
        $codeTime = explode('|', $this->getAuthenticateResetToken());
        if (empty($codeTime[1]))
            return null;
        return $codeTime[1];
    }

    /**
     * @param string|null $authenticateResetToken
     * @return UserAuthenticateInterface
     */
    public function setAuthenticateResetToken(?string $authenticateResetToken): string
    {
        if (is_null($this->getAuthenticateResetTime()) || $this->getAuthenticateResetTime() < strtotime('-24 Hours') || is_null($authenticateResetToken)) {
            $this->authenticateResetToken = $authenticateResetToken;
            return 'New';
        }
        return 'Existing';
    }

    /**
     * @return bool
     */
    public function isValidAuthenticateResetToken(): bool
    {
        return ($this->getAuthenticateResetTime() ? $this->getAuthenticateResetTime() >= strtotime('-24 Hours') : false);
    }
}