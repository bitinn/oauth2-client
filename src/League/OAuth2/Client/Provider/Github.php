<?php

namespace League\OAuth2\Client\Provider;

class Github extends IdentityProvider {

  public $scope = array();

  public $name = "github";

  public function urlAuthorize()
  {
    return 'https://github.com/login/oauth/authorize';
  }

  public function urlAccessToken()
  {
    return 'https://github.com/login/oauth/access_token';
  }

  public function urlUserDetails()
  {
    return 'https://api.github.com/user?';
  }

  public function userDetails($response, \League\OAuth2\Client\Token\AccessToken $token)
  {
    $user = new User;

    $user->uid = $response->id;
    $user->nickname = $response->login;
    $user->name = isset($response->name) && $response->name ? $response->name : null;
    $user->email = isset($response->email) && $response->email ? $response->email : null;
    $user->urls = array(
      'profile' => 'https://github.com/'.$response->login,
      'site' => isset($response->blog) && $response->blog ? $response->blog : null
    );

    return $user;
  }
}
