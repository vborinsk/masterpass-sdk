<?php

/**
 * Sign requests before performing the request.
 * 
 * @version $Id: OAuthRequestSigner.php 174 2010-11-24 15:15:41Z brunobg@corollarium.com $
 * @author Marc Worrell <marcw@pobox.com>
 * @date  Nov 16, 2007 4:02:49 PM
 * 
 * 
 * The MIT License
 * 
 * Copyright (c) 2007-2008 Mediamatic Lab
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


require_once dirname(__FILE__) . '/OAuthStore.php';
require_once dirname(__FILE__) . '/OAuthRequest.php';


class OAuthRequestSigner extends OAuthRequest
{
	
	
	protected $request;
	protected $store;
	protected $usr_id = 0;
	private   $signed = false;

	
	/**
	 * Construct the request to be signed.  Parses or appends the parameters in the params url.
	 * When you supply an params array, then the params should not be urlencoded.
	 * When you supply a string, then it is assumed it is of the type application/x-www-form-urlencoded
	 * 
	 * @param string request	url
	 * @param string method		PUT, GET, POST etc.
	 * @param mixed params 		string (for urlencoded data, or array with name/value pairs)
	 * @param string body		optional body for PUT and/or POST requests
	 */
	function __construct ( $request, $method = null, $params = null, $body = null )
	{
		// DBS
		// We do not want to rely on a session store.
		//$this->store = OAuthStore::instance();
		
		if (is_string($params))
		{
			parent::__construct($request, $method, $params);
		}
		else
		{
			parent::__construct($request, $method);
			if (is_array($params))
			{
				foreach ($params as $name => $value)
				{
					$this->setParam($name, $value);
				}
			}
		}
		
		// With put/ post we might have a body (not for application/x-www-form-urlencoded requests)
		if (strcasecmp($method, 'PUT') == 0 || strcasecmp($method, 'POST') == 0)
		{
			$this->setBody($body);
		}
	}


	/**
	 * Reset the 'signed' flag, so that any changes in the parameters force a recalculation
	 * of the signature.
	 */
	function setUnsigned ()
	{
		$this->signed = false;
	}


	/**
	 * Sign our message in the way the server understands.
	 * Set the needed oauth_xxxx parameters.
	 * 
	 * @param int usr_id		(optional) user that wants to sign this request
	 * @param array secrets		secrets used for signing, when empty then secrets will be fetched from the token registry
	 * @param string name		name of the token to be used for signing
	 * @exception OAuthException2 when there is no oauth relation with the server
	 * @exception OAuthException2 when we don't support the signing methods of the server
	 */	
	function sign ( $usr_id = 0, $secrets = null, $name = '', $token_type = null)
	{
		$url = $this->getRequestUrl();
		if (empty($secrets))
		{
			// get the access tokens for the site (on an user by user basis)
			$secrets = $this->store->getSecretsForSignature($url, $usr_id, $name);
		}
		if (empty($secrets))
		{
			throw new OAuthException2('No OAuth relation with the server for at "'.$url.'"');
		}

		$signature_method = $this->selectSignatureMethod($secrets['signature_methods']);

		$token		  = isset($secrets['token'])        ? $secrets['token']        : '';
		$token_secret = isset($secrets['token_secret']) ? $secrets['token_secret'] : '';

		if (!$token) {
			$token = $this->getParam('oauth_token');
		}

		$this->setParam('oauth_signature_method',$signature_method);
		$this->setParam('oauth_signature',		 '');
		$this->setParam('oauth_nonce', 			 !empty($secrets['nonce'])     ? $secrets['nonce']     : uniqid(''));
		$this->setParam('oauth_timestamp', 		 !empty($secrets['timestamp']) ? $secrets['timestamp'] : time());
		if ($token_type != 'requestToken')
			$this->setParam('oauth_token', 		 $token);
		$this->setParam('oauth_consumer_key',	 $secrets['consumer_key']);
		$this->setParam('oauth_version',		 '1.0');
		
		$body = $this->getBody();
		// DBS
		// The MasterCard API for transaction logging does not use the xoauth_body_signature,
		// and thus this should not be included in the signing mechanism.
		//if (!is_null($body))
		//{
		//	// We also need to sign the body, use the default signature method
		//	$body_signature = $this->calculateDataSignature($body, $secrets['consumer_secret'], $token_secret, $signature_method);
		//	$this->setParam('xoauth_body_signature', $body_signature, true);
		//}
		
		if (!array_key_exists('consumer_secret', $secrets)) $secrets['consumer_secret'] = null;
		$signature = $this->calculateSignature($secrets['consumer_secret'], $token_secret, $token_type);
		// DBS
		// Opted to URL encode after signing instead of within the signing method.
		//$this->setParam('oauth_signature',	$signature, true);
		$this->setParam('oauth_signature', urlencode($signature), true);
		
		$this->signed = true;
		$this->usr_id = $usr_id;
	}


	/**
	 * Builds the Authorization header for the request.
	 * Adds all oauth_ and xoauth_ parameters to the Authorization header.
	 * 
	 * @return string
	 */
	function getAuthorizationHeader ()
	{
		if (!$this->signed)
		{
			$this->sign($this->usr_id);
		}
		$h = array();
		///////////////////////////////////////////////////////////////////////
		// DBS
		// Added support for the realm attribute, which is required by
		// the MasterCard API URLs.
		$h[] = 'Authorization: OAuth realm="'.$this->realm.'"';

		foreach ($this->param as $name => $value)
		{
			if (strncmp($name, 'oauth_', 6) == 0 || strncmp($name, 'xoauth_', 7) == 0)
          	{
				$h[] = $name.'="'.$value.'"';
			}
		}
		$hs = implode(',', $h);
		$this->authHeader = $hs;
		return $hs;
	}


	/**
	 * Builds the application/x-www-form-urlencoded parameter string.  Can be appended as
	 * the query part to a GET or inside the request body for a POST.
	 * 
	 * @param boolean oauth_as_header		(optional) set to false to include oauth parameters
	 * @return string
	 */	
	function getQueryString ( $oauth_as_header = true )
	{
		$parms = array();
		foreach ($this->param as $name => $value)
		{
			if (	!$oauth_as_header 
				||	(strncmp($name, 'oauth_', 6) != 0 && strncmp($name, 'xoauth_', 7) != 0))
			{
				if (is_array($value))
				{
					foreach ($value as $v)
					{
						$parms[] = $name.'='.$v;
					}
				}
				else
				{
					$parms[] = $name.'='.$value;
				}
			}
		}
		return implode('&', $parms);
	}

}


/* vi:set ts=4 sts=4 sw=4 binary noeol: */

?>