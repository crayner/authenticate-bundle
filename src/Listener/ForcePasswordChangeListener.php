<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 30/03/2019
 * Time: 12:08
 */
namespace Crayner\Authenticate\Listener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Class ForcePasswordChangeListener
 * @package Crayner\Authenticate\Listener
 */
class ForcePasswordChangeListener implements EventSubscriberInterface
{

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var RouterInterface
     */
    private $router;

    /**
     * ForcePasswordChangeListener constructor.
     * @param TokenStorageInterface|null $tokenStorage
     */
    public function __construct(TokenStorageInterface $tokenStorage, RouterInterface $router)
    {
        $this->tokenStorage = $tokenStorage;
        $this->router = $router;
    }
    /**
     * getSubscribedEvents
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return [
            KernelEvents::REQUEST => array('onKernelRequest', 12),
        ];
    }


    /**
     * onKernelRequest
     * @param GetResponseEvent $event
     * @return void|RedirectResponse
     * @throws \Exception
     */
    public function onKernelRequest(GetResponseEvent $event)
    {
        if (!$event->isMasterRequest())
            return ;

        $token = $this->tokenStorage->getToken();
        if (empty($token))
            return ;
        $user = $token->getUser();

        return new RedirectResponse($this->router->generate('force_password_change', ['user' => $user->getId()]));
    }
}