<?php

namespace RabbitMQAuth\Authentication;

use RabbitMQAuth\Exception\AuthenticationFailException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

interface AuthenticationCheckerInterface
{
    /**
     * @param UserInterface  $user
     * @param TokenInterface $token
     *
     * @throws AuthenticationFailException
     */
    public function checkAuthentication(UserInterface $user, TokenInterface $token);

    /**
     * @param TokenInterface $token
     *
     * @return boolean
     */
    public function support(TokenInterface $token);
}
