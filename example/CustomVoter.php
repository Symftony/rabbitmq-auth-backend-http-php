<?php

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

class CustomVoter implements VoterInterface
{
    /**
     * @param TokenInterface $token
     * @param mixed          $subject
     * @param array          $attributes
     * @return mixed
     */
    public function vote(TokenInterface $token, $subject, array $attributes)
    {
        if ($token->getUsername() === 'admin') {
            return true;
        }

        return $subject === 'resource';
    }

    /**
     * @param mixed $attribute
     * @return mixed
     */
    public function supportsAttribute($attribute)
    {
        return true;
    }

    /**
     * @param string $class
     * @return mixed
     */
    public function supportsClass($class)
    {
        return true;
    }
}
