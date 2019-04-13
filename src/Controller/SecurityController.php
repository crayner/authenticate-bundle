<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 21/03/2019
 * Time: 13:56
 */
namespace Crayner\Authenticate\Controller;

use Crayner\Authenticate\Core\AuthenticateManager;
use Crayner\Authenticate\Core\SecurityUserProvider;
use Crayner\Authenticate\Entity\User;
use Crayner\Authenticate\Form\Type\AuthenticateType;
use Crayner\Authenticate\Form\Type\ForcePasswordChangeType;
use Crayner\Authenticate\Form\Type\PasswordByTokenType;
use Crayner\Authenticate\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

/**
 * Class SecurityController
 * @package Crayner\Core\Controller
 */
class SecurityController extends AbstractController
{
    /**
     * @param AuthenticationUtils $authenticationUtils
     * @param UserRepository $repository
     * @return \Symfony\Component\HttpFoundation\RedirectResponse|\Symfony\Component\HttpFoundation\Response
     * @Route("/login", name="login")
     */
    public function login(AuthenticationUtils $authenticationUtils, SecurityUserProvider $provider, AuthenticateManager $am)
    {
        if (! is_null($this->getUser()) && $provider->supportsClass(get_class($this->getUser())) && $this->isGranted('ROLE_USER')) {
            return $this->redirectToRoute('home');
        }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();

        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        try {
            $user = $lastUsername ? $provider->loadUserByUsername($lastUsername) : User::createUser();
        } catch ( UsernameNotFoundException $e) {
            $user = User::createUser(null, $lastUsername);
            $error = $e;
        }

        $user = $user ?: User::createUser(null, $lastUsername);

        $form = $this->createForm(AuthenticateType::class, $user, ['authenticate_manager' => $am]);

        return $this->render('@CraynerAuthenticate/Security/login.html.twig',
            [
                'form' => $form->createView(),
                'error' => $error,
                'password_reset' => $am->isMailerAvailable(),
            ]
        );
    }

    /**
     * home
     * @Route("/", name="home")
     * @Route("/home")
     */
    public function home()
    {
        return $this->render('@CraynerAuthenticate/base.html.twig');
    }

    /**
     * home
     * @Route("/test", name="test")
     *
     */
    public function test()
    {
        $this->denyAccessUnlessGranted(['ROLE_USER']);
        return $this->render('@CraynerAuthenticate/base.html.twig');
    }

    /**
     * logout
     * @Route("/logout/", name="logout")
     */
    public function logout()
    {
        throw new \RuntimeException('You must activate the logout in your security firewall configuration.');
    }

    /**
     * @param SecurityUserProvider $manager
     * @param string $username
     * @Route("/security/email/{username}/reset/token/", name="send_email_password_reset_token")
     */
    public function sendEmailPasswordResetCode(SecurityUserProvider $manager, string $username, \Swift_Mailer $mailer)
    {
        $manager->setUsername($username);
        $manager->generateAuthenticateResetCode();

        $message = (new \Swift_Message('Password Reset Email'))
            ->setFrom('noreply@'.$_SERVER['HTTP_HOST'])
            ->setTo($manager->getEmail())
            ->setBody(
                $this->renderView(
                // Resources/views/Security/send_email_password_reset.html.twig
                    '@CraynerAuthenticate/Security/send_email_password_reset.html.twig',
                    ['manager' => $manager,]
                ),
                'text/html'
            )
            /*
             * If you also want to include a plaintext version of the message
            ->addPart(
                $this->renderView(
                    'emails/registration.txt.twig',
                    ['name' => $name]
                ),
                'text/plain'
            )
            */
        ;
        $mailer->send($message);

        return $this->render('@CraynerAuthenticate/Security/confirm_email_password_reset.html.twig',
            [
                'manager' => $manager,
            ]
        );
    }

    /**
     * @param string $token
     * @param SecurityUserProvider $manager
     * @Route("/security/password/reset/{token}/by/token/", name="reset_password_by_token")
     */
    public function resetPasswordByToken(string $token, SecurityUserProvider $manager, Request $request)
    {
        if ($manager->hasValidAuthenticateResetToken($token))
        {
            $form = $this->createForm(PasswordByTokenType::class, $manager->getUser());

            $form->handleRequest($request);
            if ($form->isSubmitted() && $form->isValid())
            {
                $manager->getUser()->setAuthenticateResetToken(null);
                $manager->changePassword();
                return $this->redirectToRoute('home');
            }

            return $this->render('@CraynerAuthenticate/Security/change_password_with_token.html.twig',
                [
                    'form' => $form->createView(),
                ]
            );
        }
        return $this->render('@CraynerAuthenticate/Security/no_valid_authenticate_token.html.twig');
    }

    /**
     * @param string $token
     * @param SecurityUserProvider $manager
     * @Route("/security/password/force/{user}/change/", name="force_password_change")
     */
    public function forcePasswordChange($user, SecurityUserProvider $provider, Request $request)
    {
        $user = $provider->find($user);

        $form = $this->createForm(ForcePasswordChangeType::class, $user);

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid())
        {
            $provider->changePassword();
            return $this->redirectToRoute('home');

        }

        return $this->render('@CraynerAuthenticate/Security/force_change_user_password.html.twig',
            [
                'form' => $form->createView(),
            ]
        );
    }
}