<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 26/03/2019
 * Time: 14:15
 */
namespace Crayner\Authenticate\Entity;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Trait UserEntityTrait
 * @package Crayner\Authenticate\Entity
 */
trait UserEntityTrait
{
    /**
     * @var integer|null
     */
    private $id;

    /**
     * @return int|null
     */
    public function getId(): ?int
    {
        return $this->id;
    }

    /**
     * @var string|null
     */
    private $username;

    /**
     * @return string|null
     */
    public function getUsername(): ?string
    {
        return $this->username;
    }

    /**
     * @param string|null $username
     * @return UserInterface
     */
    public function setUsername(?string $username): UserInterface
    {
        $this->username = $username;
        return $this;
    }

    /**
     * @var string|null
     */
    private $email;

    /**
     * @return string|null
     */
    public function getEmail(): ?string
    {
        return $this->email;
    }

    /**
     * @param string|null $email
     * @return UserInterface
     */
    public function setEmail(?string $email): UserInterface
    {
        $this->email = $email;
        if (empty($this->username))
            return $this->setUsername($email);
        return $this;
    }

    /**
     * @var string|null
     */
    private $password;

    /**
     * @return string|null
     */
    public function getPassword(): ?string
    {
        return $this->password;
    }

    /**
     * @param string|null $password
     * @return UserInterface
     */
    public function setPassword(?string $password): UserInterface
    {
        $this->password = $password;
        return $this;
    }

    /**
     * @var array|null
     */
    private $roles;


    /**
     * @return array
     */
    public function getRoles(): array
    {
        if (empty($this->roles))
            $this->roles = [];
        return $this->roles;
    }

    /**
     * @param array|null $roles
     * @return UserInterface
     */
    public function setRoles(?array $roles): UserInterface
    {
        $this->roles = $roles;
        return $this;
    }

    /**
     * @param string|null $role
     * @return UserInterface
     */
    public function addRole(?string $role): UserInterface
    {
        if (empty($role) || in_array($role, $this->getRoles()))
            return $this;
        $this->roles[] = $role;
        return $this;
    }

    /**
     * @param string|null $role
     * @return UserInterface
     */
    public function removeRole(?string $role): UserInterface
    {
        if (empty($role) || ! in_array($role, $this->getRoles()))
            return $this;
        unset($this->roles[$role]);
        return $this;
    }


    /**
     * @return string
     */
    public function getSalt()
    {
        return '';
    }

    /**
     * @return UserInterface
     */
    public function eraseCredentials()
    {
        return $this->setPassword(null);
    }
}