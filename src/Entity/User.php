<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 20/03/2019
 * Time: 15:18
 */
namespace Crayner\Authenticate\Entity;

use Crayner\Authenticate\Core\UserAuthenticateInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Class User
 * @package Core\Entity
 */
class User implements UserAuthenticateInterface, EquatableInterface
{
    use UserEntityTrait;
    use UserAuthenticateTrait;

    /**
     * User constructor.
     * @param string|null $email
     * @param string|null $username
     */
    private function __construct(?string $email, ?string $username = null)
    {
        $this->email = $email;
        $this->username = $username ?: $email;
        $this->setFailureCount(0);
        $this->setLastFailureTime(null);
        $this->setEnabled(true);
        $this->setLastAuthenticateTime(new \DateTimeImmutable('now'));
    }

    /**
     * @param string|null $email
     * @param string|null $username
     * @return User
     */
    public static function createUser(?string $email = null, ?string $username = null)
    {
        return new self($email, $username);
    }

    /**
     * The equality comparison should neither be done by referential equality
     * nor by comparing identities (i.e. getId() === getId()).
     *
     * However, you do not need to compare every attribute, but only those that
     * are relevant for assessing whether re-authentication is required.
     *
     * @return bool
     */
    public function isEqualTo(UserInterface $user): bool
    {
        if ($user->getId() !== $this->getId())
            return false;

        if ($user->getUsername() !== $this->getUsername())
            return false;

        if ($user->getEmail() !== $this->getEmail())
            return false;

        if ($user->getRoles() !== $this->getRoles())
            return false;

        return true;
    }
}