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
 * Trait UserAuthenticateTrait
 * @package Crayner\Authenticate\Entity
 */
trait UserAuthenticateTrait
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

    /**
     * @var array
     */
    private $previousPasswords;

    /**
     * @return array
     */
    public function getPreviousPasswords(): array
    {
        return $this->previousPasswords ?: [];
    }

    /**
     * @param array $previousPasswords
     * @return UserAuthenticateTrait
     */
    public function setPreviousPasswords(array $previousPasswords): UserAuthenticateInterface
    {
        $this->previousPasswords = $previousPasswords;
        return $this;
    }

    /**
     * @param string $password
     * @return UserAuthenticateInterface
     */
    public function addPreviousPassword(string $password): UserAuthenticateInterface
    {
        if (in_array($password, $this->getPreviousPasswords()))
            return $this;

        $this->previousPasswords[strtotime('now')] = $password;
        return $this;
    }

    /**
     * @param string $password
     * @return UserAuthenticateInterface
     */
    public function removePreviousPassword(string $password): UserAuthenticateInterface
    {
        if (in_array($password, $this->getPreviousPasswords())) {
            $key = array_search($password, $this->previousPasswords);
            unset($this->previousPasswords[$key]);
        }
        return $this;
    }

    /**
     * @var null|string
     */
    private $rawPassword;

    /**
     * @return string|null
     */
    public function getRawPassword(): ?string
    {
        return $this->rawPassword;
    }

    /**
     * @param string|null $rawPassword
     * @return UserAuthenticateTrait
     */
    public function setRawPassword(?string $rawPassword): UserAuthenticateInterface
    {
        $this->rawPassword = $rawPassword;
        return $this;
    }

    /**
     * @var boolean
     */
    private $forcePasswordChange;

    /**
     * @return bool
     */
    public function isForcePasswordChange(): bool
    {
        return $this->forcePasswordChange ? true : false ;
    }

    /**
     * @param bool $forcePasswordChange
     * @return UserAuthenticateTrait
     */
    public function setForcePasswordChange(bool $forcePasswordChange): UserAuthenticateInterface
    {
        $this->forcePasswordChange = $forcePasswordChange ? true : false ;
        return $this;
    }
}