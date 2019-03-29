<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 27/03/2019
 * Time: 15:26
 */
namespace Crayner\Authenticate\Validator;

use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

/**
 * Class PasswordValidator
 * @package Crayner\Authenticate\Validator
 */
class PasswordValidator extends ConstraintValidator
{
    public function validate($value, Constraint $constraint)
    {
        if (mb_strlen($value) < $constraint->minLength)
            $this->context->buildViolation(sprintf($constraint->errorMessages['min_length'], $constraint->minLength))
                ->setTranslationDomain($constraint->transDomain)
                ->setParameter('{count}', $constraint->minLength)
                ->addViolation();

        if (mb_strlen($value) > $constraint->maxLength)
            $this->context->buildViolation(sprintf($constraint->errorMessages['max_length'], $constraint->maxLength + 1))
                ->setTranslationDomain($constraint->transDomain)
                ->setParameter('{count}', $constraint->maxLength)
                ->addViolation();

        if ($constraint->caseDifference && ! preg_match('/^(?=.*?[A-Z])(?=.*?[a-z])/', $value))
            $this->context->buildViolation($constraint->errorMessages['case_difference'])
                ->setTranslationDomain($constraint->transDomain)
                ->addViolation();

        if ($constraint->useNumber && ! preg_match('/[0-9]/', $value))
            $this->context->buildViolation($constraint->errorMessages['use_number'])
                ->setTranslationDomain($constraint->transDomain)
                ->addViolation();

        if ($constraint->specialCharacters && ! preg_match('/[!#@$%^&*\)\(\\\]\[:><?;+-]/', $value))
            $this->context->buildViolation($constraint->errorMessages['special_characters'])
                ->setTranslationDomain($constraint->transDomain)
                ->addViolation();
    }
}