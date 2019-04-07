<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 30/03/2019
 * Time: 15:47
 */

namespace Crayner\Authenticate\Validator;

use Crayner\Authenticate\Core\SecurityUserProvider;
use Crayner\Authenticate\Core\UserAuthenticateInterface;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

class CurrentPasswordValidValidator extends ConstraintValidator
{
    public function validate($value, Constraint $constraint)
    {
        if ($value instanceof UserAuthenticateInterface)
        {
            $password = $value->getPassword();
            $user = $this->provider->find($value->getId());
            $this->provider->getEntityManager()->refresh($user);
            if (! $this->provider->getEncoder()->isPasswordValid($value->getPassword(), $password, $value->getSalt()))
                $this->context->buildViolation($this->provider->getMessages()->getMessage('current_password_wrong'))
                    ->setTranslationDomain($this->provider->getMessages()->getTranslationDomain())
                    ->atPath('_password')
                    ->addViolation();
        }
    }

    /**
     * @var SecurityUserProvider
     */
    private $provider;

    /**
     * RotatePasswordValidator constructor.
     * @param SecurityUserProvider $provider
     */
    public function __construct(
        SecurityUserProvider $provider
    ) {
        $this->provider = $provider;
    }
}