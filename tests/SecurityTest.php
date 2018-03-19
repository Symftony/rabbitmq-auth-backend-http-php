<?php

namespace RabbitMQAuth\Tests\Controller;

use Prophecy\Prophecy\ObjectProphecy;
use Psr\Log\LoggerInterface;
use RabbitMQAuth\Authentication\Authenticator;
use RabbitMQAuth\Authentication\ChainAuthenticationChecker;
use RabbitMQAuth\Authentication\Token\UserPasswordToken;
use RabbitMQAuth\Authentication\Token\UserToken;
use RabbitMQAuth\Authentication\UserPasswordTokenChecker;
use RabbitMQAuth\Authentication\UserTokenChecker;
use RabbitMQAuth\Security;
use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;

class SecurityTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var VoterInterface|ObjectProphecy
     */
    private $voterMock;

    /**
     * @var TokenStorage
     */
    private $tokenStorage;

    /**
     * @var Security
     */
    private $security;

    /**
     * @var LoggerInterface
     */
    private $loggerMock;

    public function setUp()
    {
        $this->tokenStorage = new TokenStorage();

        $userProvider = new InMemoryUserProvider(array(
            'user1' => array(
                'password' => 'password1',
                'roles' => array('Administrator'),
            ),
            'user2' => array(
                'password' => 'password2',
            ),
        ));

        $authenticator = new Authenticator(
            $userProvider,
            new ChainAuthenticationChecker(array(
                new UserPasswordTokenChecker(),
                new UserTokenChecker(),
            ))
        );

        $authenticationManager = new AuthenticationProviderManager(array($authenticator));

        $this->voterMock = $this->prophesize('Symfony\Component\Security\Core\Authorization\Voter\VoterInterface');

        $accessDecisionManager = new AccessDecisionManager(array(
            $this->voterMock->reveal(),
        ));

        $authorizationChecker = new AuthorizationChecker(
            $this->tokenStorage,
            $authenticationManager,
            $accessDecisionManager
        );

        $this->security = new Security(
            $authenticationManager,
            $authorizationChecker
        );
    }

    /**
     * @dataProvider userPasswordTokenProvider
     */
    public function testAuthenticate($token, $expected)
    {
        $this->tokenStorage->setToken($token);

        $this->assertEquals($expected, $this->security->authenticate($token));
    }

    public function userPasswordTokenProvider()
    {
        return array(
            array(
                new UserPasswordToken(
                    'user1',
                    'password1'
                ),
                true,
            ),
            array(
                new UserPasswordToken(
                    'user1',
                    'wrong_password'
                ),
                false,
            ),
        );
    }

    /**
     * @dataProvider voterProvider
     */
    public function testVhost($voterReturn, $expected)
    {
        $token = new UserToken('user1');
        $this->voterMock
            ->vote($token, 'vhost', array('ip' => 'my_fake_ip'))
            ->willReturn($voterReturn)
            ->shouldBeCalled();

        $this->tokenStorage->setToken($token);

        $this->assertEquals($expected, $this->security->vhost($token, 'my_fake_ip'));
    }

    /**
     * @dataProvider voterProvider
     */
    public function testResource($voterReturn, $expected)
    {
        $token = new UserToken('user1');
        $this->voterMock
            ->vote($token, 'resource', array(
                'resource' => 'my_fake_resource',
                'name' => 'my_fake_name',
                'permission' => 'my_fake_permission',
            ))
            ->willReturn($voterReturn)
            ->shouldBeCalled();

        $this->tokenStorage->setToken($token);

        $this->assertEquals(
            $expected,
            $this->security->resource(
                $token,
                'my_fake_resource',
                'my_fake_name',
                'my_fake_permission'
            )
        );
    }

    /**
     * @dataProvider voterProvider
     */
    public function testTopic($voterReturn, $expected)
    {
        $token = new UserToken('user1');
        $this->voterMock
            ->vote($token, 'topic', array(
                'resource' => 'my_fake_resource',
                'name' => 'my_fake_name',
                'permission' => 'my_fake_permission',
                'routing_key' => 'my_fake_routing_key',
                'variable_map_username' => 'my_fake_variable_map_username',
                'variable_map_vhost' => 'my_fake_variable_map_vhost',
            ))
            ->willReturn($voterReturn)
            ->shouldBeCalled();

        $this->tokenStorage->setToken($token);

        $this->assertEquals(
            $expected,
            $this->security->topic(
                $token,
                'my_fake_resource',
                'my_fake_name',
                'my_fake_permission',
                'my_fake_routing_key',
                'my_fake_variable_map_username',
                'my_fake_variable_map_vhost'
            )
        );
    }

    public function voterProvider()
    {
        return array(
            array(1, true),
            array(0, false),
            array(-1, false),
        );
    }
}
