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

use Symfony\Component\Validator\Constraint;

/**
 * Class RotatePassword
 * @package Crayner\Authenticate\Validator
 */
class RotatePassword extends Constraint
{
    /**
     * @return string
     */
    public function validatedBy()
    {
        return RotatePasswordValidator::class;
    }

    /**
     * @return array|string
     */
    public function getTargets()
    {
        return Constraint::CLASS_CONSTRAINT;
    }
}