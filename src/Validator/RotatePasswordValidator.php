<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 29/03/2019
 * Time: 10:07
 */

namespace Crayner\Authenticate\Validator;


use Crayner\Authenticate\Core\SecurityUserProvider;
use Crayner\Authenticate\Core\UserAuthenticateInterface;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

class RotatePasswordValidator extends ConstraintValidator
{
    public function validate($value, Constraint $constraint)
    {
        if ($value instanceof UserAuthenticateInterface && $this->provider->isRotatingPassword())
        {
            if (! $this->provider->isValidPasswordChange())
                $this->context->buildViolation($this->provider->getRotatePassword()['message'])
                    ->setTranslationDomain($this->provider->getRotatePassword()['translation_domain'])
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