<?php

require('oauth-php/library/OAuthRequester.php');
require('Models/RequestTokenResponse.php');
require('Models/AccessTokenResponse.php');

class Connector
{
	const AMP =  "&";
	const QUESTION = "?";
	const EMPTY_STRING = "";
	const EQUALS = "=";

	const POST = "POST";
	const GET = "GET";
	const PKEY = 'pkey';
	const STRNATCMP = "strnatcmp";
	const SHA1 = "SHA1";
	const APPLICATION_XML = "application/xml";
	const AUTHORIZATION = "Authorization";
	const OAUTH_BODY_HASH = "oauth_body_hash";
	const BODY = "body";

	// Signature Base String
	const OAUTH_SIGNATURE = "oauth_signature";
	const OAUTH_CONSUMER_KEY = 'oauth_consumer_key';
	const OAUTH_NONCE = 'oauth_nonce';
	const SIGNATURE_METHOD = 'oauth_signature_method';
	const TIMESTAMP = 'oauth_timestamp';
	const OAUTH_CALLBACK = "oauth_callback";

	//Request Token Response
	const XOAUTH_REQUEST_AUTH_URL = 'xoauth_request_auth_url';
	const OAUTH_CALLBACK_CONFIRMED = "oauth_callback_confirmed";
	const OAUTH_EXPRIES_IN = "oauth_expires_in";
	const OAUTH_TOKEN_SECRET = "oauth_token_secret";

	// Callback URL paramenters
	const OAUTH_TOKEN = "oauth_token";
	const OAUTH_VERIFIER = "oauth_verifier";
	const CHECKOUT_RESOURCE_URL = "checkout_resource_url";

	// Redirect Parameters
	const CHECKOUT_IDENTIFIER = 'checkout_identifier';
	const ACCEPTABLE_CARDS = 'acceptable_cards';
	const OAUTH_VERSION = 'oauth_version';
	const VERSION = 'version';
	const SUPPRESS_SHIPPING_ADDRESS = 'suppress_shipping_address';
	const ACCEPT_REWARDS_PROGRAM = 'accept_reward_program';
	const SHIPPING_LOCATION_PROFILE = 'shipping_location_profile';
	const DEFAULT_XMLVERSION = "v1";
	const AUTH_LEVEL = "auth_level";
	const BASIC = "basic";
	const XML_VERSION_REGEX = "/v[0-9]+/";

	// Srings to detect errors in the service calls
	const ERRORS_TAG = "<Errors>";
	const HTML_TAG = "<html>";
	const HTML_BODY_OPEN = '<body>';
	const HTML_BODY_CLOSE = '</body>';

	// Error Messages
	const EMPTY_REQUEST_TOKEN_ERROR_MESSAGE = 'Invalid Request Token';
	const INVAILD_AUTH_URL = 'Invalid Auth Url';
	const POSTBACK_ERROR_MESSAGE = 'Postback Transaction Call was unsuccessful';

	// Our OAuth session instance.
	private $oAuthRequester;

	public $signatureBaseString;
	public $authHeader;

	public $consumerKey;
	public $requestUrl;
	private $shoppingCartUrl;
	public $accessUrl;
	public $callBackUrl;
	public $transactionUrl;
	public $realm;
	public $privateKey;
	private $checkoutIdentifier;

	public $keystorePath;
	public $keystorePassword;

	public $oauthSecrets;

	private $version = '1.0';
	private $signatureMethod = 'RSA-SHA1';

	private $requestTokenInfo; // Returned by the getRequestToken method.

	public function __construct($consumerKey, $requestUrl,$shoppingCartUrl, $accessUrl, $transactionUrl, $realmType)
	{
		$this->consumerKey = $consumerKey;
		$this->requestUrl = $requestUrl;
		$this->shoppingCartUrl = $shoppingCartUrl;
		$this->accessUrl = $accessUrl;
		$this->transactionUrl = $transactionUrl;
		$this->realm = $realmType;
	}

	/**
	 * SDK:
	 * This constructor allows the caller to provide a keystore path and keystore password
	 * from which to load a keystore's private key.
	 * @param $consumerKey
	 * @param $keystorePath
	 * @param $keystorePassword
	 * @param $requestUrl
	 * @param $shoppingCartUrl
	 * @param $accessUrl
	 * @param $transactionUrl
	 * @param $realmType
	 */
	public static function connectorFromKeystore($consumerKey,$keystorePath, $keystorePassword, $requestUrl,$shoppingCartUrl, $accessUrl, $transactionUrl, $realmType)
	{
		$instance = new self($consumerKey, $requestUrl,$shoppingCartUrl, $accessUrl, $transactionUrl, $realmType);
		$instance->keystorePath = $keystorePath;
		$instance->keystorePassword = $keystorePassword;

		return $instance;
	}

	/**
	 * SDK:
	 * This constructor allows the caller to provide a preloaded private key for use when
	 * OAuth calls are made.
	 * @param $consumerKey
	 * @param $privateKey
	 * @param $requestUrl
	 * @param $shoppingCartUrl
	 * @param $accessUrl
	 * @param $transactionUrl
	 * @param $realmType
	 */
	public static function connectorFromPrivateKey($consumerKey, $privateKey, $requestUrl,$shoppingCartUrl, $accessUrl, $transactionUrl, $realmType)
	{
		$instance = new self($consumerKey, $requestUrl,$shoppingCartUrl, $accessUrl, $transactionUrl, $realmType);
		$instance->privateKey = $privateKey;

		return $instance;
	}

	/**
	 * SDK:
	 * This method gets a request token and constructs the redirect URL
	 * @param $callbackUrl
	 * @param $acceptableCards
	 * @param $checkoutProjectId
	 * @param $xmlVersion
	 * @param $shippingSupression
	 * @param $rewardsProgram
	 * @param $authLevelBasic
	 * @return Output is a RequestTokenResponse object containing all data returned from this method
	 */
	public function getRequestTokenAndRedirectUrl($callbackUrl,$acceptableCards,$checkoutProjectId,$xmlVersion,$shippingSupression, $rewardsProgram, $authLevelBasic,$shippingLocationProfile) {
		$return = $this->getRequestToken($callbackUrl);
		$return->redirectURL = $this->getConsumerSignInUrl($acceptableCards, $checkoutProjectId, $xmlVersion, $shippingSupression, $rewardsProgram, $authLevelBasic,$shippingLocationProfile);
		return $return;
	}

	/**
	 * SDK:
	 * This method posts the Shopping Cart data to MasterCard services
	 * and is used to display the shopping cart in the wallet site.
	 * @param $ShoppingCartXml
	 * @return Output is the response from MasterCard services
	 */
	public function postShoppingCartData($ShoppingCartXml)
	{
		$params = array(
				Connector::OAUTH_BODY_HASH => $this->generateBodyHash($ShoppingCartXml)
		);

		$response = $this->doRequest($params,$this->shoppingCartUrl,Connector::POST,$ShoppingCartXml);
		return  $response;
	}

	/**
	 * This method Gets the Access Token and Checkout Resources and stores them in a map.
	 * @param $requestToken
	 * @param $verifier
	 * @param $checkoutResourceUrl
	 * @return AccessTokenResponse
	 */
	public function GetAccessTokenAndCheckoutResources($requestToken, $verifier, $checkoutResourceUrl)
	{
		$return = new AccessTokenResponse();
		$return->requestToken = $requestToken;
		$return->verifier = $verifier;
		$return->checkoutResourceUrl = $checkoutResourceUrl;

		$token = $this->GetAccessToken($requestToken, $verifier);
		$return->accessTokenCallAuthHeader = $this->authHeader;
		$return->accessTokenCallSignatureBaseString = $this->signatureBaseString;
		$return->accessToken = $token[Connector::OAUTH_TOKEN];
		$return->oauthSecret = $token[Connector::OAUTH_TOKEN_SECRET];

		$return->paymentShippingResource = $this->GetPaymentShippingResource($return->accessToken, $return->checkoutResourceUrl);

		return $return;
	}

	/**
	 * This method submits the receipt transaction list to MasterCard as a final step
	 * in the Wallet process.
	 * @param $merchantTransactions
	 * @return Output is the response from MasterCard services
	 */
	public function PostCheckoutTransaction($merchantTransactions)
	{
		$params = array(
				Connector::OAUTH_BODY_HASH => $this->generateBodyHash($merchantTransactions)
		);

		$response = $this->doRequest($params,$this->transactionUrl,Connector::POST,$merchantTransactions);

		return  $response;
	}
	/**
	 * Encodes all ASCII character to there decimal encodings
	 * @param $string
	 */
	public static function AllHtmlEncode($str){

		// get rid of existing entities else double-escape
		$str = html_entity_decode(stripslashes($str),ENT_QUOTES,'UTF-8');
		$ar = preg_split('/(?<!^)(?!$)/u', $str );  // return array of every multi-byte character
		foreach ($ar as $c){
			$o = ord($c);
			if ( (strlen($c) > 127) || /* multi-byte [unicode] */
			($o > 127))				  /*Encodes everything above ascii 127*/
			{
				// convert to numeric entity
				$c = mb_encode_numericentity($c,array (0x0, 0xffff, 0, 0xffff), 'UTF-8');
			}
			$str2 .= $c;
		}
		return $str2;
	}

	public static function encodeShoppingCartRequest(SimpleXMLElement $shoppingCartData)
	{
		foreach($shoppingCartData->ShoppingCart->ShoppingCartItem as $item){
			$item->Description = Connector::AllHtmlEncode((string)$item->Description);
		}
		return $shoppingCartData;
	}



	/*************** Private Methods *****************************************************************************************************************************/
	/**
	 * SDK:
	 * Get the user's request token and store it in the current user session.
	 * @param $callbackUrl
	 * @return RequestTokenResponse
	 */
	private function GetRequestToken($callbackUrl)
	{
		$params = array(
				Connector::OAUTH_CALLBACK => $callbackUrl
		);

		$response = $this->doRequest($params,$this->requestUrl,Connector::POST,null);
		$requestTokenInfo = $this->parseConnectionResponse($response);

		$return = new RequestTokenResponse();
		$return->requestToken = $requestTokenInfo[Connector::OAUTH_TOKEN];
		$return->authorizeUrl =  $requestTokenInfo[Connector::XOAUTH_REQUEST_AUTH_URL];
		$return->callbackConfirmed =  $requestTokenInfo[Connector::OAUTH_CALLBACK_CONFIRMED];
		$return->oauthexpiresIn =  $requestTokenInfo[Connector::OAUTH_EXPRIES_IN];
		$return->oauthSecret =  $requestTokenInfo[Connector::OAUTH_TOKEN_SECRET];

		$this->requestTokenInfo = $return;

		// Return the request token response class.
		return $return;
	}

	/**
	 * SDK:
	 * Assuming that all due diligence is done and assuming the presence of an established session,
	 * successful reception of non-empty request token, and absence of any unanticipated
	 * exceptions have been successfully verified, you are ready to go to the authorization
	 * link hosted by MasterCard.
	 * @param $acceptableCards
	 * @param $checkoutProjectId
	 * @param $xmlVersion
	 * @param $shippingSupression
	 * @param $rewardsProgram
	 * @param $authLevelBasic
	 * @throws Exception
	 * @return string
	 */
	private function GetConsumerSignInUrl($acceptableCards, $checkoutProjectId, $xmlVersion,$shippingSupression
										 ,$rewardsProgram,$authLevelBasic,$shippingLocationProfile )
	{
		$baseAuthUrl = $this->requestTokenInfo->authorizeUrl;
		
		$xmlVersion = strtolower ($xmlVersion);
			
		// Use v1 if xmlVersion does not match correct patern
		if (!preg_match(Connector::XML_VERSION_REGEX, $xmlVersion)){
			$xmlVersion = Connector::DEFAULT_XMLVERSION;
		}

		$token = $this->requestTokenInfo->requestToken;
		if ($token == null || $token == Connector::EMPTY_STRING) {
			throw new Exception(Connector::EMPTY_REQUEST_TOKEN_ERROR_MESSAGE);
		}

		if ($baseAuthUrl == null || $baseAuthUrl == Connector::EMPTY_STRING) {
			throw new Exception(Connector::INVAILD_AUTH_URL);
		}
			
		// construct the Redirect URL
		$finalAuthUrl = $baseAuthUrl .
		$this->getParamString(Connector::ACCEPTABLE_CARDS,$acceptableCards,true).
		$this->getParamString(Connector::CHECKOUT_IDENTIFIER,$checkoutProjectId) .
		$this->getParamString(Connector::OAUTH_TOKEN,$token).
		$this->getParamString(Connector::VERSION,$xmlVersion);

		// If xmlVersion is v1 (default version), then shipping suppression, rewardsprogram and auth_level are not used
		if(strcasecmp($xmlVersion, Connector::DEFAULT_XMLVERSION) != 'v1') {
			$finalAuthUrl = $finalAuthUrl.$this->getParamString(Connector::SUPPRESS_SHIPPING_ADDRESS,$shippingSupression);

			if((int)substr($xmlVersion,1) >= 4){
				$finalAuthUrl = $finalAuthUrl.$this->getParamString(Connector::ACCEPT_REWARDS_PROGRAM, $rewardsProgram);
			}

			if($authLevelBasic) {
				$finalAuthUrl = $finalAuthUrl.$this->getParamString(Connector::AUTH_LEVEL,CONNECTOR::BASIC);
			}
			
			if( (int)substr($xmlVersion,1) >= 4 && $shippingLocationProfile != null && !empty($shippingLocationProfile) ){
				$finalAuthUrl = $finalAuthUrl.$this->getParamString(Connector::SHIPPING_LOCATION_PROFILE, $shippingLocationProfile);
			}
		}
		return $finalAuthUrl;
	}

// 	public function addShippingProfile($redirectUrl,$shippingProfile){
// 		$redirectUrl = $redirectUrl.$this->getParamString(Connector::SHIPPING_LOCATION_PROFILE, $shippingProfile);
// 		return $redirectUrl;
// 	}

	/**
	 * SDK:
	 * This method captures the Checkout Resource URL and Request Token Verifier
	 * and uses these to request the Access Token.
	 * @param $requestToken
	 * @param $verifier
	 * @return Output is Access Token
	 */
	private function GetAccessToken($requestToken, $verifier)
	{
		$params = array(
				Connector::OAUTH_VERIFIER => $verifier,
				Connector::OAUTH_TOKEN => $requestToken
		);

		$response = $this->doRequest($params,$this->accessUrl,Connector::POST,null);

		$token = $this->parseConnectionResponse($response);

		return $token;
	}

	/**
	 * SDK:
	 * This method retrieves the payment and shipping information
	 * for the current user/session.
	 * @param unknown $accessToken
	 * @param unknown $checkoutResourceUrl
	 * @return Output is the Checkout XML string containing the users billing and shipping information
	 */
	private function GetPaymentShippingResource($accessToken, $checkoutResourceUrl)
	{
		$params = array(
				Connector::OAUTH_TOKEN => $accessToken
		);

		$response = $this->doRequest($params,$checkoutResourceUrl,Connector::GET,null);
		return  $response;
	}

	/**
	 * SDK:
	 * Method to generate the body hash
	 * @param $body
	 * @return string
	 */
	private function generateBodyHash($body) {
		$sha1Hash = sha1($body, true);
		return base64_encode($sha1Hash);
	}

	/**
	 * SDK:
	 * Method to create the URL with GET Parameters
	 * @param $key
	 * @param $value
	 * @param $firstParam
	 * @return string
	 */
	private function getParamString($key,$value,$firstParam = false) {
		$paramString = Connector::EMPTY_STRING;
			
		if ($firstParam) {
			$paramString .= Connector::QUESTION;
		} else {
			$paramString .= Connector::AMP;
		}
		$paramString .= $key.Connector::EQUALS.$value;
			
		return $paramString;
	}

	/**
	 * This method generates and returns a unique nonce value to be used in
	 *	Wallet API OAuth calls.
	 * @param $length
	 * @return string
	 */
	private function generateNonce($length){
		if (function_exists('com_create_guid') === true)
		{
			return trim(com_create_guid(), '{}');
		}
		else
		{
			$u = md5(uniqid('nonce_', true));
			return substr($u,0,$length);
		}
	}

	// Metod used to save the signature base string and authorization header after each connection
	private function saveConnectionData($OAuthRequester){
		$this->signatureBaseString = $OAuthRequester->signatureBaseStr;
		$this->authHeader = $OAuthRequester->authHeader;
	}

	// Method used to parse the connection response and return a array of the data
	private function parseConnectionResponse($response){
		$token  = array();
		foreach (explode('&', $response) as $p)
		{
			@list($name, $value) = explode('=', $p, 2);
			$token[$name] = urldecode($value);
		}
		return $token;
	}

	// Set the the common connection settings
	private function setSecrets()
	{
		$nonce = $this->generateNonce(16);
		$time = time();

		$this->oauthSecrets = array(
				'consumer_key'		=> $this->consumerKey,
				'signature_methods'	=> array('RSA-SHA1'),
				'nonce'				=> $nonce,
				'timestamp'			=> $time
		);

	}

	// Method used for all Http connections
	private function doRequest($params,$url,$requestMethod,$body){


		$oAuthRequester = new OAuthRequester($url, $requestMethod,'');
		// Initialize the secrets.
		$this->setSecrets();

		if (!is_null($this->privateKey))
			$oAuthRequester->privateKey = $this->privateKey;
		else
		{
			$oAuthRequester->keyStorePath = $this->keystorePath;
			$oAuthRequester->keyStorePassword = $this->keystorePassword;
		}
			
		// Set all connection parameters
		foreach ($params as $key => $value)
		{
			$oAuthRequester->setParam($key, $value);
		}

		if($body != null){
			$oAuthRequester->setBody($body);
		}
		else {
			$oAuthRequester->realm = $this->realm;
		}

		try {
			$requestInfo = $oAuthRequester->doRequest($this->oauthSecrets);
		}
		catch (Exception $e) {
			$this->saveConnectionData($oAuthRequester);
			throw $this->checkForErrors($e);
		}
		$this->saveConnectionData($oAuthRequester);
		return $requestInfo[Connector::BODY];
	}

	// Method to check for HTML content in the exception message and remove everything except the body
	private function checkForErrors(Exception $e){
		if( strpos($e->getMessage(), Connector::HTML_TAG ) !== false) {
			$body= substr($e->getMessage(),strpos($e->getMessage(),Connector::HTML_BODY_OPEN)+6,strpos ($e->getMessage(),Connector::HTML_BODY_CLOSE));
			return new Exception($body);
		}
		else {
			return $e;
		}
	}
}
