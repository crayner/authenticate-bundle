<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 23/11/2018
 * Time: 15:27
 */
namespace Crayner\Authenticate\Core;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Guard\Authenticator\AbstractFormLoginAuthenticator;

/**
 * Class LoginFormAuthenticator
 * @package Crayner\Authenticate\Core
 */
class LoginFormAuthenticator extends AbstractFormLoginAuthenticator
{
    use TargetPathTrait;

    CONST FAILURE_DETAILS = '_security.failure_details';
    /**
     * @var EntityManagerInterface
     */
    private $entityManager;

    /**
     * @var RouterInterface
     */
    private $router;

    /**
     * @var CsrfTokenManagerInterface
     */
    private $csrfTokenManager;

    /**
     * @var PasswordEncoderInterface
     */
    private $passwordEncoder;

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * LoginFormAuthenticator constructor.
     * @param EntityManagerInterface $entityManager
     * @param RouterInterface $router
     * @param CsrfTokenManagerInterface $csrfTokenManager
     * @param PasswordEncoderInterface $passwordEncoder
     * @param TokenStorageInterface $tokenStorage
     */
    public function __construct(
        EntityManagerInterface $entityManager,
        RouterInterface $router,
        CsrfTokenManagerInterface $csrfTokenManager,
        TokenStorageInterface $tokenStorage
    ) {
        $this->entityManager = $entityManager;
        $this->router = $router;
        $this->csrfTokenManager = $csrfTokenManager;
        $this->tokenStorage = $tokenStorage;
    }

    /**
     * @param PasswordEncoderInterface $passwordEncoder
     * @return LoginFormAuthenticator
     */
    public function setPasswordEncoder(PasswordEncoderInterface $passwordEncoder): LoginFormAuthenticator
    {
        $this->passwordEncoder = $passwordEncoder;
        return $this;
    }

    /**
     * supports
     * @param Request $request
     * @return bool
     */
    public function supports(Request $request)
    {
        return 'login' === $request->attributes->get('_route')
            && $request->isMethod('POST') && $this->passwordEncoder instanceof HighestAvailableEncoder;
    }

    /**
     * getCredentials
     * @param Request $request
     * @return array|mixed
     */
    public function getCredentials(Request $request)
    {
        if ($this->isSessionLocked($request))
            throw new CustomUserMessageAuthenticationException(sprintf('The device has been blocked from further authentication attempts for "%s" minutes.', $this->getSessionLockTime($request)));

        $authenticate = $request->request->get('authenticate');
        $credentials = [
            'email' => $authenticate['_username'],
            'password' => $authenticate['_password'],
            'csrf_token' => $authenticate['_token'],
        ];
        $request->getSession()->set(
            Security::LAST_USERNAME,
            $credentials['email']
        );

        return $credentials;
    }

    /**
     * getUser
     * @param mixed $credentials
     * @param UserProviderInterface $userProvider
     * @return object|UserInterface|null
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $token = new CsrfToken('authenticate', $credentials['csrf_token']);
        if (!$this->csrfTokenManager->isTokenValid($token)) {
            throw new InvalidCsrfTokenException();
        }

        $repository = $this->entityManager->getRepository($this->getUserClass());

        $user = $repository->loadUserByUsername($credentials['email']);

        if (!$user) {
            // fail authentication with a custom error
            throw new CustomUserMessageAuthenticationException('Username/Email could not be found.');
        }

        return $user;
    }

    /**
     * @var UserInterface
     */
    private $user;

    /**
     * @param mixed $credentials
     * @param UserInterface $user
     * @return bool
     * @throws \Doctrine\ORM\NonUniqueResultException
     */
    public function checkCredentials($credentials, UserInterface $user): bool
    {
        $this->user = $user;

        // Is the user locked?
        if (! $user->isEnabled()) {
            throw new CustomUserMessageAuthenticationException(sprintf('The user "%s" is not enabled to access the site.', $user->getUsername()));
        }
        // Is user temporarily locked?
        $this->requestUser = $user;
        if ($this->isUserLocked(null))
            return false;

        $valid = $this->passwordEncoder->isPasswordValid($user->getPassword(), $credentials['password'], $user->getSalt());
        return $valid;
    }

    /**
     * @param Request $request
     * @param TokenInterface $token
     * @param string $providerKey
     * @return RedirectResponse|\Symfony\Component\HttpFoundation\Response|null
     * @throws \Exception
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        //store the token blah blah blah
        $this->tokenStorage->setToken($token);
        $session = $request->getSession();
        $time = strtotime('now');
        $session->set('last_activity_time', $time);
        $session->save();

        $this->clearFailures($request);
        if ($this->hasValidRequestUser($request)) {
            $this->entityManager->refresh($this->getRequestUser($request));
            $this->getRequestUser($request)->setLastAuthenticateTime(new \DateTimeImmutable('now'));
            $this->entityManager->persist($this->getRequestUser($request));
            $this->entityManager->flush();
        }
        $targetPath = $this->getTargetPath($request, $providerKey);

        return new RedirectResponse($targetPath ?: '/');
    }

    /**
     * @param Request $request
     * @param AuthenticationException $exception
     * @return RedirectResponse
     * @throws \Doctrine\ORM\NonUniqueResultException
     * @throws \Exception
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $message = 'Authentication failed. Is your username and password correct?';
        if ($this->hasFailureManagement()) {
            if ($this->isSessionLocked($request))
                $message = sprintf('The device has been blocked from further authentication attempts for "%s" minutes.', $this->getSessionLockTime($request));
            if ($this->isUserLocked($request))
                $message = sprintf('The user "%s" has been blocked from further authentication attempts for "%s" minutes.', $this->getUserName($request), $this->getUserLockTime($request));

            $this->incSessionLock($request);
            $this->incUserLock($request);
        }

        $exception = new CustomUserMessageAuthenticationException($message);

        if ($this->hasValidRequestUser($request)) {
            $this->getRequestUser($request)->setLastAuthenticateTime(new \DateTimeImmutable('now'));
            $this->entityManager->persist($this->getRequestUser($request));
            $this->entityManager->flush();
        }

        return parent::onAuthenticationFailure($request, $exception);
    }

    /**
     * getLoginUrl
     * @return string
     */
    protected function getLoginUrl()
    {
        return $this->router->generate('login');
    }

    /**
     * supportsRememberMe
     * @return bool
     */
    public function supportsRememberMe()
    {
        return false;
    }

    /**
     * @var array
     */
    private $failureConfig;

    /**
     * @return array
     */
    public function getFailureConfig(): array
    {
        return $this->failureConfig;
    }

    /**
     * @param array $failureConfig
     * @return LoginFormAuthenticator
     */
    public function setFailureConfig(array $failureConfig): LoginFormAuthenticator
    {
        $this->failureConfig = $failureConfig;
        return $this;
    }

    /**
     * @return bool
     */
    private function hasFailureManagement(): bool
    {
        return $this->failureConfig['count'] > 0 && $this->failureConfig['wait_time'] > 0;
    }

    /**
     * @param Request $request
     * @return bool
     */
    private function isSessionLocked(Request $request): bool
    {
        if (! $this->getFailureConfig()['session']) return false;
        $fd = $this->getSessionFailureDetails($request);
        if ($fd['count'] >= $this->getFailureConfig()['count'])
        {
            if ($fd['last_failure'] < strtotime('now') - ($this->getFailureConfig()['wait_time'] * 60))
            {
                $fd['count'] = 0;
                $fd['last_failure'] = null;
            }
        }

        $this->setSessionFailureDetails($fd, $request);
        return ($fd['count'] >= $this->getFailureConfig()['count']);
    }

    /**
     * @var array
     */
    private $sessionFailureDetails;

    /**
     * @param Request $request
     * @return array
     */
    private function getSessionFailureDetails(Request $request): array
    {
        if (! empty($this->sessionFailureDetails))
            return $this->sessionFailureDetails;
        $session = $request->getSession();
        $this->sessionFailureDetails = $session->has(self::FAILURE_DETAILS) ? $session->get(self::FAILURE_DETAILS) : ['count' => 0, 'last_failure' => null];
        return $this->sessionFailureDetails;
    }

    /**
     * @param array $details
     * @param Request $request
     * @return LoginFormAuthenticator
     */
    private function setSessionFailureDetails(array $details, ?Request $request): LoginFormAuthenticator
    {
        $this->sessionFailureDetails = $details;
        if (is_null($request) || ! $this->getFailureConfig()['session']) return $this;
        $session = $request->getSession();
        $session->set(self::FAILURE_DETAILS, $details);
        return $this;
    }

    /**
     * @param Request $request
     * @return LoginFormAuthenticator
     */
    private function incSessionLock(Request $request): LoginFormAuthenticator
    {
        if (($this->hasValidRequestUser($request) && $this->getFailureConfig()['user']) || ! $this->getFailureConfig()['session'])
            return $this;
        $fd = $this->getSessionFailureDetails($request);
        $fd['count']++;
        if ($fd['count'] < $this->getFailureConfig()['count'])
            $fd['last_failure'] = strtotime('now');

        return $this->setSessionFailureDetails($fd, $request);
    }

    /**
     * @param Request $request
     * @return string
     */
    private function getSessionLockTime(Request $request): string
    {
        $fd = $this->getSessionFailureDetails($request);
        $time = $fd['last_failure'] - strtotime('-'.$this->getFailureConfig()['wait_time'].' minutes');
        return date('i:s', $time);
    }

    /**
     * @param Request $request
     * @return LoginFormAuthenticator
     */
    private function clearSessionFailure(Request $request): LoginFormAuthenticator
    {
        if ($this->getFailureConfig()['session'])
            $request->getSession()->remove(self::FAILURE_DETAILS);
        return $this;
    }

    /**
     * @param Request $request
     * @return bool
     * @throws \Doctrine\ORM\NonUniqueResultException
     */
    private function isUserLocked(?Request $request): bool
    {
        if (! $this->getFailureConfig()['user']) return false;
        $fd = $this->getUserFailureDetails($request);
        if (empty($fd)) return false;
        if ($fd['count'] >= $this->getFailureConfig()['count'])
        {
            if ($fd['last_failure'] < strtotime('now') - ($this->getFailureConfig()['wait_time'] * 60))
            {
                $fd['count'] = 0;
                $fd['last_failure'] = null;
            }
        }
        $this->setUserFailureDetails($fd, $this->getRequestUser($request));

        return ($fd['count'] >= $this->getFailureConfig()['count']);
    }

    /**
     * @var array
     */
    private $userFailureDetails;

    /**
     * @param Request $request
     * @return array|null
     * @throws \Doctrine\ORM\NonUniqueResultException
     */
    private function getUserFailureDetails(?Request $request): ?array
    {
        if (! empty($this->userFailureDetails))
            return $this->userFailureDetails;
        $this->getRequestUser($request);
        if (! $this->hasValidRequestUser($request)) return null;
        $fd = [];
        $fd['count'] = $this->requestUser->getFailureCount();
        $fd['last_failure'] = $this->requestUser->getLastFailureTime();
        return $this->setUserFailureDetails($fd, $this->getRequestUser($request))->getUserFailureDetails($request);
    }

    /**
     * @param array $details
     * @param UserAuthenticateInterface $user
     * @return LoginFormAuthenticator
     */
    private function setUserFailureDetails(array $details, UserAuthenticateInterface $user): LoginFormAuthenticator
    {
        $this->userFailureDetails = $details;
        $user->setLastFailureTime($this->getFailureConfig()['user'] ? $details['last_failure'] : null);
        $user->setFailureCount($this->getFailureConfig()['user'] ? $details['count'] : 0);
        $this->entityManager->persist($user);
        $this->entityManager->flush();
        $this->requestUser = $user;
        return $this;
    }

    /**
     * @var string
     */
    private $userClass;

    /**
     * @return string
     */
    public function getUserClass(): string
    {
        return  $this->userClass;
    }

    /**
     * @param string $userClass
     * @return LoginFormAuthenticator
     */
    public function setUserClass(string $userClass): LoginFormAuthenticator
    {
        $this->userClass = $userClass;
        if (! class_exists($this->userClass) || ! in_array(UserAuthenticateInterface::class, class_implements($this->userClass)))
            throw new \InvalidArgumentException(sprintf('The user class "%s" must exist and must implement "%s"', $userClass,UserAuthenticateInterface::class));
        return $this;
    }

    /**
     * @param Request $request
     * @return LoginFormAuthenticator
     * @throws \Doctrine\ORM\NonUniqueResultException
     */
    private function incUserLock(Request $request): LoginFormAuthenticator
    {
        $fd = $this->getUserFailureDetails($request);
        if (empty($fd)) return $this;
        $fd['count']++;
        if ($fd['count'] < $this->getFailureConfig()['count'])
            $fd['last_failure'] = strtotime('now');

        return $this->setUserFailureDetails($fd, $this->getRequestUser($request));
    }

    /**
     * @var UserAuthenticateInterface
     */
    private $requestUser;

    /**
     * @param Request|null $request
     * @return UserAuthenticateInterface|null
     */
    private function getRequestUser(?Request $request): ?UserAuthenticateInterface
    {
        if (! empty($this->requestUser))
            return $this->requestUser;
        $session = $request->getSession();
        $lastUsername = $session->get(Security::LAST_USERNAME);
        if (!$this->requestUser instanceof UserInterface || $this->requestUser->getUsername() !== $lastUsername )
            $this->requestUser = $this->entityManager->getRepository($this->getUserClass())->loadUserByUsername($lastUsername);
        return $this->requestUser;
    }

    /**
     * @param Request $request
     * @return string
     */
    private function getUserName(Request $request): string
    {
        $this->getRequestUser($request);
        return $this->requestUser->getUsername();
    }

    /**
     * @param Request|null $request
     * @return string
     * @throws \Doctrine\ORM\NonUniqueResultException
     */
    private function getUserLockTime(?Request $request): string
    {
        $fd = $this->getUserFailureDetails($request);
        $time = $fd['last_failure'] - strtotime('-'.$this->getFailureConfig()['wait_time'].' minutes');
        return date('i:s', $time);
    }

    /**
     * @param Request|null $request
     * @return bool
     */
    private function hasValidRequestUser(?Request $request): bool
    {
        $this->getRequestUser($request);
        return ($this->requestUser instanceof UserAuthenticateInterface);
    }

    /**
     * @param Request $request
     * @return LoginFormAuthenticator
     */
    private function clearFailures(Request $request): LoginFormAuthenticator
    {
        return $this->clearUserFailure($request)->clearSessionFailure($request);
    }

    /**
     * @param Request $request
     * @return LoginFormAuthenticator
     */
    private function clearUserFailure(Request $request): LoginFormAuthenticator
    {
        $this->getRequestUser($request);
        $this->entityManager->refresh($this->requestUser);
        $this->requestUser->setFailureCount(0);
        $this->requestUser->setLastFailureTime(null);
        $this->entityManager->persist($this->requestUser);
        $this->entityManager->flush();
        return $this;
    }
}
