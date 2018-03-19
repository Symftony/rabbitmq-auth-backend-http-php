<?php

namespace RabbitMQAuth\Authentication;

use RabbitMQAuth\Authentication\Token\UserPasswordToken;
use RabbitMQAuth\Exception\AuthenticationFailException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class UserPasswordTokenChecker extends UserTokenChecker
{
    /**
     * @param UserInterface  $user
     * @param TokenInterface $token
     */
    public function checkAuthentication(UserInterface $user, TokenInterface $token)
    {
        parent::checkAuthentication($user, $token);

        if ($user->getPassword() !== $token->getCredentials()) {
            $this->logger->debug(sprintf('Wrong Password. "%s" ≠ "%s".', $user->getPassword(), $token->getCredentials()), array('user' => $user, 'token' => $token));
            throw new AuthenticationFailException('Wrong Password.');
        }
    }

    /**
     * @param TokenInterface $token
     *
     * @return bool
     */
    public function support(TokenInterface $token)
    {
        return $token instanceof UserPasswordToken;
    }
}
