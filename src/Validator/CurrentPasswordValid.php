<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 30/03/2019
 * Time: 15:45
 */
namespace Crayner\Authenticate\Validator;

use Symfony\Component\Validator\Constraint;

/**
 * Class CurrentPasswordValid
 * @package Crayner\Authenticate\Validator
 */
class CurrentPasswordValid extends Constraint
{
    /**
     * @return string
     */
    public function validatedBy()
    {
        return CurrentPasswordValidValidator::class;
    }

    /**
     * @return array|string
     */
    public function getTargets()
    {
        return Constraint::CLASS_CONSTRAINT;
    }
}