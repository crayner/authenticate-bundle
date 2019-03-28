<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 21/03/2019
 * Time: 13:52
 */
namespace Crayner\Authenticate\Form\Type;

use Crayner\Authenticate\Core\UserAuthenticateInterface;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ButtonType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Class AuthenticateType
 * @package Crayner\Authenticate\Form\Type
 */
class AuthenticateType extends AbstractType
{
    /**
     * buildForm
     * @param FormBuilderInterface $builder
     * @param array $options
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder
            ->add('_username', TextType::class,
                [
                    'attr' => [
                        'placeholder' => 'Username or email',
                        'autocomplete' => 'username',
                    ],
                    'label' => 'Username or email',
                ]
            )->add('_password', PasswordType::class,
                [
                    'attr' => [
                        'placeholder' => 'Password',
                        'autocomplete' => 'current-password',
                    ],
                    'label' => 'Password',
                ]
            )->add('submit', SubmitType::class)
        ;

        if ($options['authenticate_manager']->isMailerAvailable())
            $builder->add('reset_password', ButtonType::class,
                [
                    'attr' => ['onClick' => 'resetPassword()']
                ]
            );
    }

    /**
     * getBlockPrefix
     *
     * @return null|string
     */
    public function getBlockPrefix()
    {
        return 'authenticate';
    }

    /**
     * configureOptions
     *
     * @param OptionsResolver $resolver
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setRequired(
            [
                'authenticate_manager',
            ]
        );
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