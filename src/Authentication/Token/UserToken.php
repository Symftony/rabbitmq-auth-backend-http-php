<?php

namespace RabbitMQAuth\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class UserToken extends AbstractToken
{
    /**
     * @var string
     */
    private $username;

    /**
     * @var null
     */
    private $vhost;

    /**
     * @var mixed
     */
    private $user;

    /**
     * @var boolean
     */
    private $isAuthenticated;

    /**
     * @param string $username
     * @param null  $vhost
     * @param array $roles
     */
    public function __construct($username, $vhost = null, array $roles = array())
    {
        parent::__construct($roles);

        $this->username = $username;
        $this->vhost = $vhost;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->username;
    }

    /**
     * @return null
     */
    public function getCredentials()
    {
        return '';
    }

    /**
     * @return mixed
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * @param object|string $user
     * @return $this
     */
    public function setUser($user)
    {
        $this->user = $user;

        return $this;
    }

    /**
     * Returns the username.
     *
     * @return string
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @return bool
     */
    public function isAuthenticated()
    {
        return $this->isAuthenticated;
    }

    /**
     * @param $isAuthenticated
     *
     * @return $this
     */
    public function setAuthenticated($isAuthenticated)
    {
        $this->isAuthenticated = $isAuthenticated;

        return $this;
    }
}

