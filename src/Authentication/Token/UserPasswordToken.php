<?php

namespace RabbitMQAuth\Authentication\Token;

class UserPasswordToken extends UserToken
{
    /**
     * @var null
     */
    private $password;

    /**
     * @param string $username
     * @param null   $password
     * @param null   $vhost
     * @param array  $roles
     */
    public function __construct($username, $password, $vhost = null, array $roles = array())
    {
        parent::__construct($username, $vhost, $roles);

        if (null === $password) {
            throw new \InvalidArgumentException('Password require.');
        }

        $this->password = $password;
    }

    /**
     * @return null
     */
    public function getCredentials()
    {
        return $this->password;
    }
}

