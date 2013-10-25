<?php

namespace League\OAuth2\Client\Provider;

class Facebook extends IdentityProvider {

  public $scopes = array('email', 'user_about_me');

  public $name = "facebook";

  public function urlAuthorize()
  {
    return 'https://www.facebook.com/dialog/oauth';
  }

  public function urlAccessToken()
  {
    return 'https://graph.facebook.com/oauth/access_token';
  }

  public function urlUserDetails()
  {
    return 'https://graph.facebook.com/me?';
  }

  public function userDetails($response, \League\OAuth2\Client\Token\AccessToken $token)
  {
    $imageHeaders = get_headers('https://graph.facebook.com/me/picture?type=normal&access_token='.$token->accessToken, 1);

    $user = new User;

    $user->uid = $response->id;
    $user->nickname = isset($response->username) && $response->username ? $response->username : null;
    $user->name = isset($response->name) && $response->name ? $response->name : null;
    $user->firstName = isset($response->first_name) && $response->first_name ? $response->first_name : null;
    $user->lastName = isset($response->last_name) && $response->last_name ? $response->last_name : null;
    $user->email = isset($response->email) && $response->email ? $response->email : null;
    $user->location = isset($response->hometown->name) && $response->hometown->name ? $response->hometown->name : null;
    $user->description = isset($response->bio) && $response->bio ? $response->bio : null;
    $user->imageUrl = isset($imageHeaders['Location']) && $imageHeaders['Location'] ? $imageHeaders['Location'] : null;
    $user->urls = array(
      'profile' => $response->link,
    );

    return $user;
  }
}
