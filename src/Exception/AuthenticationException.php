<?php

namespace RabbitMQAuth\Exception;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class AuthenticationException extends \RuntimeException
{
    /**
     * @var TokenInterface
     */
    private $token;

    /**
     * @param TokenInterface $token
     *
     * @return AuthenticationException
     */
    public function setToken($token)
    {
        $this->token = $token;

        return $this;
    }

    /**
     * @return TokenInterface
     */
    public function getToken()
    {
        return $this->token;
    }
}
