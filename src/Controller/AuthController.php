<?php

namespace RabbitMQAuth\Controller;

use RabbitMQAuth\Authentication\Token\UserPasswordToken;
use RabbitMQAuth\Authentication\Token\UserToken;
use RabbitMQAuth\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class AuthController
{
    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var Security
     */
    private $security;

    /**
     * @param TokenStorageInterface $tokenStorage
     * @param Security              $security
     */
    public function __construct(TokenStorageInterface $tokenStorage, Security $security)
    {
        $this->tokenStorage = $tokenStorage;
        $this->security = $security;
    }

    public function userAction(Request $request)
    {
        $token = new UserPasswordToken(
            $request->get('username'),
            $request->get('password')
        );
        $this->tokenStorage->setToken($token);

        if ($this->security->authenticate($token)) {
            return new Response(sprintf('Allow %s', implode(' ', $token->getUser()->getRoles())));
        }

        return new Response('Deny');
    }

    public function vhostAction(Request $request)
    {
        $token = new UserToken($request->get('username'));
        $this->tokenStorage->setToken($token);

        $hasAccess = $this->security->vhost($token, $request->get('ip'));

        return new Response($hasAccess ? 'Allow' : 'Deny');
    }

    public function topicAction(Request $request)
    {
        $token = new UserToken($request->get('username'));
        $this->tokenStorage->setToken($token);

        $hasAccess = $this->security->topic(
            $token,
            $request->get('resource'),
            $request->get('name'),
            $request->get('permission'),
            $request->get('routing_key'),
            $request->get('variable_map_username'),
            $request->get('variable_map_vhost')
        );

        return new Response($hasAccess ? 'Allow' : 'Deny');
    }

    public function resourceAction(Request $request)
    {
        $token = new UserToken($request->get('username'));
        $this->tokenStorage->setToken($token);

        $hasAccess = $this->security->resource(
            $token,
            $request->get('resource'),
            $request->get('name'),
            $request->get('permission')
        );

        return new Response($hasAccess ? 'Allow' : 'Deny');
    }
}
