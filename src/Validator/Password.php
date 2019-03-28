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

/**
 * Class Password
 * @package Crayner\Authenticate\Validator
 */
class Password extends Constraint
{
    /**
     * @var bool
     */
    public $caseDifference;

    /**
     * @var bool
     */
    public $specialCharacters;

    /**
     * @var bool
     */
    public $useNumber;

    /**
     * @var integer
     */
    public $minLength;

    /**
     * @var integer
     */
    public $maxLength;

    /**
     * @var array
     */
    public $errorMessages;

    /**
     * @var string
     */
    public $transDomain = 'validators';

    /**
     * @param array $details
     */
    public function setPasswordValidation(array $details): void
    {
        $this->caseDifference = $details['case_difference'];
        $this->minLength = $details['min_length'];
        $this->maxLength = $details['max_length'];
        if ($details['max_length'] < $details['min_length'])
            $details['max_length'] = $details['min_length'];
        $this->useNumber = $details['use_number'];
        $this->specialCharacters = $details['special_characters'];
        $this->errorMessages = $details['error_messages'];
        $this->transDomain = $details['translation_domain'];
    }

    /**
     * @return string
     */
    public function validatedBy()
    {
        return PasswordValidator::class;
    }
}