<?php

namespace RabbitMQAuth\Authorization;

use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use RabbitMQAuth\Authentication\Token\UserToken;

class DefaultVoter implements VoterInterface
{
    use LoggerAwareTrait;

    /**
     * @var array
     */
    private $permissions;

    /**
     * @param $permissions
     *
     * $permissions = arrray(
     *     '{USERNAME}' => array(
     *         '{VHOST}' => array(
     *             'ip' => '{REGEX_IP}',
     *             'read' => '{REGEX_READ}',
     *             'write' => '{REGEX_WRITE}',
     *             'configure' => '{REGEX_CONFIGURE}',
     *         ),
     *     ),
     * );
     */
    public function __construct($permissions)
    {
        $this->permissions = $permissions;
        $this->logger = new NullLogger();
    }

    /**
     * @param TokenInterface $token
     * @param mixed          $subject
     * @param array          $attributes
     *
     * @return mixed
     */
    public function vote(TokenInterface $token, $subject, array $attributes)
    {
        if (isset($this->permissions[$token->getUsername()]['isAdmin'])) {
            $this->logger->info(
                'Token allow: Admin has all grant.',
                ['subject' => $subject, 'attributes' => $attributes]
            );

            return true;
        }

        if (!in_array($subject, ['vhost', 'resource', 'topic'])) {
            $this->logger->notice(
                sprintf('Token deny: subject unknow "%s".', $subject),
                ['subject' => $subject, 'attributes' => $attributes]
            );

            return false;
        }

        $permissionType = $subject === 'vhost' ? 'ip' : $attributes['permission'];
        $permissionSubject = $subject === 'vhost' ? $attributes['ip'] : $attributes['name'];

        if (!isset($this->permissions[$token->getUsername()][$token->getVhost()][$permissionType])) {
            $this->logger->notice(
                sprintf('Token deny: permission "%s->%s" not configured.', $token->getVhost(), $permissionType),
                ['subject' => $subject, 'attributes' => $attributes]
            );

            return false;
        }

        $permission = $this->permissions[$token->getUsername()][$token->getVhost()][$permissionType];
        $vote = (bool)preg_match('/' . $permission . '/', $permissionSubject);

        $this->logger->info(
            sprintf('Token %s.', $vote ? 'allow' : 'deny'),
            ['subject' => $subject, 'attributes' => $attributes]
        );

        return $vote;
    }

    /**
     * @param mixed $attribute
     *
     * @return mixed
     */
    public function supportsAttribute($attribute)
    {
        return true;
    }

    /**
     * @param string $class
     *
     * @return mixed
     */
    public function supportsClass($class)
    {
        return $class instanceof UserToken;
    }
}
