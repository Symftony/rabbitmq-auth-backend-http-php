<?php

namespace RabbitMQAuth\Tests\Controller;

use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;
use RabbitMQAuth\Authentication\Token\UserToken;
use RabbitMQAuth\Controller\AuthController;
use RabbitMQAuth\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\User\User;

class AuthControllerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var TokenStorage
     */
    private $tokenStorage;

    /**
     * @var Security|ObjectProphecy
     */
    private $securityMock;

    /**
     * @var AuthController
     */
    private $authController;

    public function setUp()
    {
        $this->tokenStorage = new TokenStorage();

        $this->securityMock = $this->prophesize('RabbitMQAuth\Security');

        $this->authController = new AuthController(
            $this->tokenStorage,
            $this->securityMock->reveal()
        );
    }

    public function testUserAction()
    {
        $this->securityMock
            ->authenticate(Argument::that(function ($token) {
                $token->setUser(new User('user', 'user_password', array('role1', 'role2')));

                return $token->getUsername() == 'user' && $token->getCredentials() == 'user_password';
            }))
            ->willReturn(true)
            ->shouldBeCalled();

        $response = $this->authController->userAction(
            new Request(array('username' => 'user', 'password' => 'user_password'))
        );

        $this->assertEquals('Allow role1 role2', $response->getContent());
    }

    /**
     * @dataProvider securityProvider
     */
    public function testVhostAction($security, $expectedResponse)
    {
        $this->securityMock
            ->vhost(
                new UserToken('user'),
                'fake_ip'
            )
            ->willReturn($security)
            ->shouldBeCalled();

        $response = $this->authController->vhostAction(
            new Request(array('username' => 'user', 'ip' => 'fake_ip'))
        );

        $this->assertEquals($expectedResponse, $response->getContent());
    }

    /**
     * @dataProvider securityProvider
     */
    public function testTopicAction($security, $expectedResponse)
    {
        $this->securityMock
            ->topic(
                new UserToken('user'),
                'my_fake_resource',
                'my_fake_name',
                'my_fake_permission',
                'my_fake_routing_key',
                'my_fake_variable_map_username',
                'my_fake_variable_map_vhost'
            )
            ->willReturn($security)
            ->shouldBeCalled();

        $response = $this->authController->topicAction(
            new Request(array(
                'username' => 'user',
                'resource' => 'my_fake_resource',
                'name' => 'my_fake_name',
                'permission' => 'my_fake_permission',
                'routing_key' => 'my_fake_routing_key',
                'variable_map_username' => 'my_fake_variable_map_username',
                'variable_map_vhost' => 'my_fake_variable_map_vhost',
            ))
        );

        $this->assertEquals($expectedResponse, $response->getContent());
    }

    /**
     * @dataProvider securityProvider
     */
    public function testResourceAction($security, $expectedResponse)
    {
        $this->securityMock
            ->resource(
                new UserToken('user'),
                'my_fake_resource',
                'my_fake_name',
                'my_fake_permission'
            )
            ->willReturn($security)
            ->shouldBeCalled();

        $response = $this->authController->resourceAction(
            new Request(array(
                'username' => 'user',
                'resource' => 'my_fake_resource',
                'name' => 'my_fake_name',
                'permission' => 'my_fake_permission',
            ))
        );

        $this->assertEquals($expectedResponse, $response->getContent());
    }

    public function securityProvider()
    {
        return array(
            array(true, 'Allow'),
            array(false, 'Deny')
        );
    }
}
