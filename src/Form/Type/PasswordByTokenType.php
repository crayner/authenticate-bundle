<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 27/03/2019
 * Time: 14:58
 */
namespace Crayner\Authenticate\Form\Type;

use Crayner\Authenticate\Core\UserAuthenticateInterface;
use Crayner\Authenticate\Validator\Password;
use Crayner\Authenticate\Validator\PasswordByAuthenticationResetToken;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Class PasswordByTokenType
 * @package Crayner\Authenticate\Form\Type
 */
class PasswordByTokenType extends AbstractType
{
    /**
     * @var Password
     */
    private $passwordValidator;

    /**
     * PasswordByTokenType constructor.
     * @param Password $password
     */
    public function __construct(Password $password)
    {
        $this->passwordValidator = $password;
    }

    /**
     * buildForm
     * @param FormBuilderInterface $builder
     * @param array $options
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder
            ->add('authenticateResetToken', HiddenType::class)
            ->add('_password', RepeatedType::class, [
                'type' => PasswordType::class,
                'invalid_message' => 'The password fields must match.',
                'options' => ['attr' => ['class' => 'password-field']],
                'required' => true,
                'first_options'  => [
                    'label' => 'Password',
                    'constraints' => [
                        $this->passwordValidator,
                    ],
                ],
                'second_options' => ['label' => 'Repeat Password'],
            ]
            )->add('submit', SubmitType::class)
        ;
    }

    /**
     * getBlockPrefix
     *
     * @return null|string
     */
    public function getBlockPrefix()
    {
        return 'password_by_token';
    }

    /**
     * configureOptions
     *
     * @param OptionsResolver $resolver
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults(
            [
                'translation' => 'messages',
                'data_class' => UserAuthenticateInterface::class,
                'attr' => [
                    'novalidate' => true,
                    'id' => $this->getBlockPrefix(),
                ],
            ]
        );
    }
}