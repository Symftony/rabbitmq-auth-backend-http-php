<?php

require_once '../vendor/autoload.php';
require_once 'bootstrap.php';

$authController->topicAction(
    \Symfony\Component\HttpFoundation\Request::createFromGlobals()
)->send();
