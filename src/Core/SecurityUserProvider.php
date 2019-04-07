<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 12/02/2019
 * Time: 16:20
 */
namespace Crayner\Authenticate\Core;

use Crayner\Authenticate\Entity\User;
use Crayner\Authenticate\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Class SecurityUserProvider
 * @package App\Core
 */
class SecurityUserProvider implements UserProviderInterface
{
    /**
     * Loads the user for the given username.
     *
     * This method must throw UsernameNotFoundException if the user is not
     * found.
     *
     * @param string $username The username
     *
     * @return UserInterface
     *
     * @throws UsernameNotFoundException if the user is not found
     */
    public function loadUserByUsername($username): UserInterface
    {
        if (null === ($user = $this->userRepository->loadUserByUsername($username))) {
            throw new UsernameNotFoundException(sprintf('No user found for "%s"', $username));
        }

        $this->setUser($user);
        return $this->getUser();
    }

    /**
     * Refreshes the user.
     *
     * It is up to the implementation to decide if the user data should be
     * totally reloaded (e.g. from the database), or if the UserInterface
     * object can just be merged into some internal array of users / identity
     * map.
     *
     * @return UserInterface
     *
     * @throws UnsupportedUserException  if the user is not supported
     * @throws UsernameNotFoundException if the user is not found
     */
    public function refreshUser(UserInterface $user): UserInterface
    {
        if (! $this->supportsClass(get_class($user)))
            throw new UnsupportedUserException(sprintf('The user provided was not valid.'));
        if ($this->supportsClass(get_class($user)) && $this->getUser() && $this->getUser()->isEqualTo($user))
            return $this->getUser();
        if ($user instanceof UserInterface)
           $user = $this->loadUserByUsername($user->getUsername());

        $this->setUser($user);
        return $this->getUser();
    }

    /**
     * Whether this provider supports the given user class.
     *
     * @param string $class
     *
     * @return bool
     */
    public function supportsClass($class): bool
    {
        return $class === $this->getUserClass() || $class === UserAuthenticateInterface::class;
    }

    /**
     * @var User|null
     */
    private $user;

    /**
     * getUser
     * @return User|null
     */
    public function getUser(): ?User
    {
        return $this->user;
    }

    /**
     * @param User|null $user
     * @return SecurityUserProvider
     */
    public function setUser(?User $user): SecurityUserProvider
    {
        $this->user = $user;
        return $this;
    }

    /**
     * @var UserRepository|null
     */
    private $userRepository;

    /**
     * @return UserRepository|null
     */
    public function getUserRepository(): ?UserRepository
    {
        return $this->userRepository;
    }

    /**
     * @param UserRepository|null $userRepository
     * @return SecurityUserProvider
     */
    public function setUserRepository(?UserRepository $userRepository): SecurityUserProvider
    {
        $this->userRepository = $userRepository;
        return $this;
    }

    /**
     * @var HighestAvailableEncoder
     */
    private $encoder;

    /**
     * @var Messages
     */
    private $messages;

    /**
     * SecurityUserProvider constructor.
     * @param UserRepository $repository
     */
    public function __construct(EntityManagerInterface $em, HighestAvailableEncoder $encoder, Messages $messages)
    {
        $this->userRepository = $em->getRepository(User::class);
        $this->entityManager = $em;
        $this->encoder = $encoder;
        $this->messages = $messages;
    }

    /**
     * @return SecurityUserProvider
     */
    public function setUsername(string $username): SecurityUserProvider
    {
        $this->loadUserByUsername($username);
        return $this;
    }

    /**
     * @param $method
     * @param $arguments
     */
    public function __call($method, $arguments)
    {
        if (method_exists($this->getUser(), $method))
        {
            if (strpos($method, 'get') === 0 || strpos($method, 'is') === 0)
                return $this->getUser()->$method();
            if (strpos($method, 'set') === 0)
                return $this->getUser()->$method($arguments[0]);
        }
        throw new \InvalidArgumentException(sprintf('The call to "%s" in the user entity was not available.', $method));
    }

    /**
     * @var string|null
     */
    private $result;

    /**
     * @return string
     */
    public function generateAuthenticateResetCode()
    {
        $this->result = $this->user->setAuthenticateResetToken(uniqid('', true).'|'.strtotime('now'));
        $this->getEntityManager()->persist($this->user);
        $this->getEntityManager()->flush();
        return $this;
    }

    /**
     * @var EntityManagerInterface
     */
    private $entityManager;

    /**
     * @return EntityManagerInterface
     */
    public function getEntityManager(): EntityManagerInterface
    {
        return $this->entityManager;
    }

    /**
     * @return string|null
     */
    public function getResult(): ?string
    {
        return $this->result;
    }

    /**
     * @param $token
     */
    private function findOneByAuthenticateResetToken(string $token)
    {
        $this->setUser($this->getUserRepository()->findOneByAuthenticateResetToken($token));
        return $this->getUser();
    }

    /**
     * @param string $token
     */
    public function hasValidAuthenticateResetToken(string $token): bool
    {
        $this->findOneByAuthenticateResetToken($token);
        if (empty($this->getUser()))
            return false;
        return $this->getUser()->isValidAuthenticateResetToken();
    }

    /**
     * @return HighestAvailableEncoder
     */
    public function getEncoder(): HighestAvailableEncoder
    {
        return $this->encoder;
    }

    /**
     * @param UserAuthenticateInterface $user
     */
    public function saveUser(UserAuthenticateInterface $user): void
    {
        $this->getEntityManager()->persist($user);
        $this->getEntityManager()->flush();
    }

    /**
     * @var string
     */
    private $userClass;

    /**
     * @return string
     */
    public function getUserClass(): string
    {
        return $this->userClass;
    }

    /**
     * @param string $userClass
     * @return SecurityUserProvider
     */
    public function setUserClass(string $userClass): SecurityUserProvider
    {
        $this->userClass = $userClass;
        return $this;
    }

    /**
     * @var array
     */
    private $rotatePassword;

    /**
     * @return array
     */
    public function getRotatePassword(): array
    {
        return $this->rotatePassword;
    }

    /**
     * @param array $rotatePassword
     * @return SecurityUserProvider
     */
    public function setRotatePassword(array $rotatePassword): SecurityUserProvider
    {
        $this->rotatePassword = $rotatePassword;
        return $this;
    }

    /**
     * @return bool
     */
    public function isRotatingPassword(): bool
    {
        return $this->getRotatePassword()['keep_last_number'] > 0 && $this->getRotatePassword()['keep_for_days'] > 0;
    }

    /**
     * @return bool
     */
    public function isValidPasswordChange(): bool
    {
        if (! $this->isRotatingPassword())
            return true;
        $password = $this->getUser()->getRawPassword();
        if ($this->getEncoder()->isPasswordValid($this->getUser()->getPassword(), $password, $this->getUser()->getSalt()))
            return false;
        $password = $this->getEncoder()->encodePassword($password, $this->getUser()->getSalt());

        $passwords = $this->cullPreviousPasswords();

        return ! in_array($password, $passwords);
    }

    /**
     * @var array|null
     */
    private $previousPasswords;

    /**
     * @return array
     */
    private function cullPreviousPasswords(): array
    {
        if (! empty($this->previousPasswords))
            return $this->previousPasswords;

        $passwords = $this->getUser()->getPreviousPasswords();
        krsort($passwords, SORT_NUMERIC);
        foreach($passwords as $time=>$password)
        {
            if ($time < strtotime('-'.$this->getRotatePassword()['keep_for_days'].' Days'))
                unset($passwords[$time]);
            else
                break;
        }

        if (count($passwords) > $this->getRotatePassword()['keep_last_number'])
        {
            while (count($passwords) > $this->getRotatePassword()['keep_last_number'])
                array_pop($passwords);

        }
        $this->getUser()->setPreviousPasswords($passwords);

        return $this->previousPasswords = $this->getUser()->getPreviousPasswords();
    }

    public function changePassword(): void
    {
        $passwords = null;
        if ($this->isRotatingPassword() && $this->isValidPasswordChange()) {
            $passwords = $this->cullPreviousPasswords();
            if (count($passwords) + 1 > $this->getRotatePassword()['keep_last_number'])
                array_pop($passwords);
            $passwords[strtotime('now')] = $this->getUser()->getPassword();
        }
        $this->getUser()->setPassword($this->getEncoder()->encodePassword($this->getUser()->getRawPassword(), $this->getUser()->getSalt()));
        $this->getUser()->setFailureCount(0);
        $this->getUser()->setPreviousPasswords($passwords);
        $this->getUser()->setForcePasswordChange(false);
        $this->saveUser($this->getUser());

    }

    /**
     * @param int $id
     * @return UserAuthenticateInterface|null
     */
    public function find(int $id): ?UserAuthenticateInterface
    {
        $this->setUser($this->getUserRepository()->find($id));
        return $this->getUser();
    }

    /**
     * @return Messages
     */
    public function getMessages(): Messages
    {
        return $this->messages;
    }
}