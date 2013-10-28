<?php namespace League\OAuth2\Client\Provider;

use League\OAuth2\Client\Token\AccessToken as AccessToken;
use League\OAuth2\Client\Grant\GrantInterface as GrantInterface;
use League\OAuth2\Client\Exception\IDPException as IDPException;

use Guzzle\Http\Client as GuzzleClient;

abstract class IdentityProvider {

  // app id
  public $clientId = '';

  // client secret
  public $clientSecret = '';

  // URL in your app where users will be sent after authorization
  public $redirectUri = '';

  // indicates the provider API access your application is requesting
  public $scopes = array();

  // the type of data to be returned in the response from the authorization server
  public $responseType = 'code';

  // request method(default 'post')
  public $method = 'post';

  public $name;

  public $scopeSeperator = ',';

  // http client
  protected $http_client;


  /**
   * Construct do opitons initialization
   *
   * @param  array  OAuth request parameters(options)
   * 
   */
  public function __construct($options = array())
  {
    // request parameter setting
    foreach ($options as $option => $value)
    {
      if (isset($this->{$option}))
      {
        $this->{$option} = $value;
      }
    }
    
    // use Guzzle HTTP client  
    $this->http_client = new GuzzleClient();
  }


  abstract public function urlAuthorize();

  abstract public function urlAccessToken();

  abstract public function urlUserDetails(AccessToken $token);

  abstract protected function userDetails($response, AccessToken $token);


  /**
   * OAuth authorization
   *
   * @param   array   authorization request options
   * @return  void 
   */
  public function authorize($options = array())
  {
    // an unguessable random string
    $state = md5(uniqid(rand(), true));

    // used to protect against cross-site request forgery attacks 
    setcookie($this->name . '_authorize_state', $state);

    $params = array(
      'client_id' => $this->clientId,
      'redirect_uri' => $this->redirectUri,
      'state' => $state,
      'scope' => is_array($this->scopes) ? implode($this->scopeSeperator, $this->scopes) : $this->scopes,
      'response_type' => isset($options['response_type']) ? $options['response_type'] : $this->responseType,
    );

    // google force-recheck this option
    if (isset($this->approval_prompt))
    {
      $params['approval_prompt'] = $this->approval_prompt;
    }

    // google need this option to obtain refersh token
    if (isset($this->access_type))
    {
      $params['access_type'] = $this->access_type;
    }

    // google provide this options as a hit to the authentication server
    if (isset($this->login_hint))
    {
      $param['login_hint'] = $this->login_hint;
    }

    $url = $this->urlAuthorize() . '?' . http_build_query($params);

    // need user grant
    header('Location: ' . $url);
    exit;
  }


  /**
   * Get access token
   *
   * @param   Object   a GrantInterface implementer 
   * @param   array    request access token options
   * @return  object 
   */
  public function getAccessToken(GrantInterface $grant, $params = array())
  {
    $defaultParams = array(
      'client_id'     => $this->clientId,
      'client_secret' => $this->clientSecret,
      'redirect_uri'  => $this->redirectUri,
      'grant_type'    => $grant,
    );

    // prepare request parameters
    $requestParams = $grant->prepRequestParams($defaultParams, $params);

    // request access token(json format)
    switch ($this->method) {
      case 'get':
        $request = $this->http_client->get($this->urlAccessToken() . '?' . http_build_query($requestParams));
        break;
      case 'post':
        $request = $this->http_client->post($this->urlAccessToken(), array(), $requestParams);
        break;
    }

    // set header
    $request->setHeader('Accept', 'application/json');

    // use proxy
    $request->getCurlOptions()->set('CURLOPT_PROXY', '127.0.0.1:7005');
    $request->getCurlOptions()->set('CURLOPT_PROXYTYPE', 'CURLPROXY_SOCKS5');

    // requests that receive a 4xx or 5xx response will throw 
    // a Guzzle\Http\Exception\BadResponseException
    try 
    {
      $response = $request->send();
    }
    catch (\Guzzle\Http\Exception\BadResponseException $e)
    {
      $raw_response = $e->getResponse();
      if (($message = json_decode($raw_response->getBody())) !== NULL)
      {
        throw new IDPException($message);
      }
      $body = parse_str($raw_response->getBody(), $body);
      throw new IDPException($body);
    }

    // parse and use a JSON response as an array using the json() method of a response
    $result = $response->json();

   return $grant->handleResponse($result); 
  }


  /**
   * Get use detail profile
   *
   * @param   string  access token
   * @return  array   user profile
   */
  public function getUserDetails(AccessToken $token)
  {
    // access the user profile API url 
    $url = $this->urlUserDetails($token);

    $request = $this->http_client->get($url);

    $request->setHeader('Accept', 'application/json');
    // use proxy
    $request->getCurlOptions()->set('CURLOPT_PROXY', '127.0.0.1:7005');
    $request->getCurlOptions()->set('CURLOPT_PROXYTYPE', 'CURLPROXY_SOCKS5');

    // requests that receive a 4xx or 5xx response will throw a Guzzle\Http\Exception\BadResponseException
    try
    {
      $response = $request->send();
    }
    catch (\Guzzle\Http\Exception\BadResponseException $e)
    {
      $raw_response = $e->getResponse();
      if (($message = json_decode($raw_response->getBody())) !== NULL)
      {
        throw new IDPException($message);
      }
      $body = parse_str($raw_response->getBody(), $body);
      throw new IDPException($body);
    }

    // parse and use a JSON response as an array using the json() method of a response
    $result = $response->json();
    return $this->userDetails($result, $token);
  }


  /**
   * A basic all api action(only supporting RESTful api)
   *
   * @param   string  http method
   * @param   string  request url
   * @param   string  request parameters
   * @return  array   response(convert json to array)
   */
  public function callApi($method, $url, $params)
  {
    switch ($method) {
      case 'get':
        $request = $http_client->get($url . '?' . http_build_query($params));
        break;
      case 'post':
        $request = $http_client->post($url, array(), $params);
        break;
      case 'put':
        $request = $http_client->put($url, array(), $params);
        break;
      case 'delete':
        $request = $http_client->delete($url, array(), $params);
        break;
      case 'patch':
        $request = $http_client->patch($url, array(), $params);
        break;
      default:
        throw new \InvalidArgumentException('HTTP method {$method} is not supported');
    }

    $request->setHeader('Accept', 'application/json');

    try
    {
      $response = $request->send();
    }
    catch (\Guzzle\Http\Exception\BadResponseException $e)
    {
      $raw_response = $e->getResponse();
      if (($result = json_decode($raw_response->getBody())) === NULL)
      {
        $result = array();
        $result['status'] = $raw_response->getStatusCode();
        $result['body'] = $raw_response->getBody();
      }
    }

    if (!isset($result))
    {
      $result = $response->json();
    }

    return $result;
  }
}
