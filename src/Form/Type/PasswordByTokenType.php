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
use Crayner\Authenticate\Validator\RotatePassword;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\NotBlank;

/**
 * Class PasswordByTokenType
 * @package Crayner\Authenticate\Form\Type
 */
class PasswordByTokenType extends AbstractType
{
    /**
     * @var RotatePassword
     */
    private $rotatePassword;

    /**
     * @var Password
     */
    private $password;

    /**
     * PasswordByTokenType constructor.
     * @param Password $password
     * @param RotatePassword $rotatePassword
     */
    public function __construct(Password $password, RotatePassword $rotatePassword)
    {
        $this->password = $password;
        $this->rotatePassword = $rotatePassword;
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
            ->add('rawPassword', RepeatedType::class, [
                'type' => PasswordType::class,
                'invalid_message' => 'The password fields must match.',
                'options' => ['attr' => ['class' => 'password-field']],
                'required' => true,
                'first_options'  => [
                    'label' => 'Password',
                    'constraints' => [
                        $this->password,
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
                'constraints' => [
                    $this->rotatePassword,
                ],
            ]
        );
    }
}