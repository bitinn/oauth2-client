<?php

namespace League\OAuth2\Client\Provider;

class Microsoft extends IdentityProvider {

  public $scopes = array('wl.basic', 'wl.emails');

  public $name = "microsoft";

  public function urlAuthorize()
  {
    return 'https://oauth.live.com/authorize';
  }

  public function urlAccessToken()
  {
    return 'https://oauth.live.com/token';
  }

  public function urlUserDetails()
  {
    return 'https://apis.live.net/v5.0/me?';
  }

  public function userDetails($response, \League\OAuth2\Client\Token\AccessToken $token)
  {
    $imageHeaders = get_headers('https://apis.live.net/v5.0/'.$response->id.'/picture', 1);

    $user = new User;

    $user->uid = $response->id;
    $user->name = isset($response->name) && $response->name ? $response->name : null;
    $user->firstName = isset($response->first_name) && $response->first_name ? $response->first_name : null;
    $user->lastName = isset($response->last_name) && $response->last_name ? $response->last_name : null;
    $user->email = isset($response->emails->preferred) && $response->emails->preferred ? $response->emails->preferred : null;
    $user->imageUrl = isset($imageHeaders['Location']) && $imageHeaders['Location'] ? $imageHeaders['Location'] : null;
    $user->urls = array(
      'profile' => $response->link.'/cid-'.$response->id,
    );

    return $user;
  }
}
