<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * OAuth 2.0 authorisation server library
 * 
 * @category  Library
 * @package   CodeIgniter
 * @author    Alex Bilbie <alex@alexbilbie.com>
 * @copyright 2012 Alex Bilbie
 * @license   MIT Licencse http://www.opensource.org/licenses/mit-license.php
 * @version   Version 0.2.1 (MongoDB converted by Eric Beekman<eric@nul76.nl>)
 * @link      https://github.com/alexbilbie/CodeIgniter-OAuth-2.0-Server
 */
class Oauth_server
{
	/**
	 * CodeIgniter instance.
	 * 
	 * @var $ci
	 * @access public
	 */
	protected $ci;

	/**
	 * Constructor
	 * 
	 * @access public
	 * @return void
	 */

	public function __construct()
	{
		$this->ci = get_instance();
		
		require_once(APPPATH.'/libraries/Mongo_db.php');
		$this->ci->load->library('mongo_db');
	}
		
	/**
	 * Validates a client's credentials
	 * 
	 * @param string $client_id     The client ID
	 * @param mixed  $client_secret The client secred
	 * @param mixed  $redirect_uri  The redirect URI
	 * 
	 * @access public
	 * @return bool|object
	 */
	public function validate_client($client_id = '', $client_secret = NULL, $redirect_uri = NULL)
	{
		$params = array(
			'client_id' => $client_id,
		);
		
		if ($client_secret !== NULL)
		{
			$params['client_secret'] = $client_secret;
		}
		
		if ($redirect_uri !== NULL)
		{
			$params['redirect_uri'] = $redirect_uri;
		}
	
		$client_check_query = $this->ci->mongo_db
										->select(array('name', 'client_id', 'auto_approve'))
										->get_where('applications', $params);
						
		if (count($client_check_query) === 1)
		{
			return (object) $client_check_query[0];
		}
		else
		{
			return FALSE;
		}
	}
		
	/**
	 * Generates a new authorise code once a user has approved an application
	 * 
	 * @param mixed $client_id    The client ID
	 * @param mixed $user_id      The user ID
	 * @param mixed $redirect_uri The client redirect URI
	 * @param array $scopes       The scopes that the client is requesting
	 * @param mixed $access_token Optional access token to be updated with a new authorisation code
	 * 
	 * @access public
	 * @return string
	 */
	public function new_auth_code($client_id = '', $user_id = '', $redirect_uri = '', $scopes = array(), $access_token = NULL)
	{		
		// Update an existing session with the new code
		if ($access_token !== NULL)
		{
			$code = md5(time().uniqid());
			
			$this->ci->mongo_db
						->where(array(
							'type_id'		=> $user_id,
							'type'			=> 'user',
							'client_id'		=> $client_id,
							'access_token'	=> $access_token
						))
						->set(array(
							'code'			=> $code,
							'stage'			=> 'request',
							'redirect_uri'	=> $redirect_uri, // The applications redirect URI may have been updated
							'last_updated'	=> new MongoDate(strtotime('now'))
						))
						->update('oauth_sessions');
				
			return $code;
		}
		
		// Create a new oauth session
		else
		{
			// Delete any existing sessions just to be sure
			$this->ci->mongo_db
						->where(array(
							'client_id'		=> $client_id,
							'type_id'		=> $user_id,
							'type'			=> 'user'
						))
						->delete('oauth_sessions');
		
			$code = md5(time().uniqid());
			
			$session_id = $this->ci->mongo_db
						->insert('oauth_sessions', array(
							'client_id'			=>	$client_id,
							'redirect_uri'		=>	$redirect_uri,
							'type_id'			=>	$user_id,
							'type'				=>	'user',
							'code'				=>	$code,
							'first_requested'	=>  new MongoDate(strtotime('now')),
							'last_updated'		=>	new MongoDate(strtotime('now')),
							'stage'				=>	'request',
							'access_token'		=>	NULL
						));
					
			//$session_id = $this->ci->mongo_db->insert_id();
			
			// Add the scopes
			foreach ($scopes as $scope)
			{
				$scope = trim($scope);
				
				if(trim($scope) !== '')
				{
					$this->ci->mongo_db
								->insert('oauth_session_scopes', array(
									'session_id'	=>	$session_id,
									'scope'			=>	$scope
								));
				}
			}
		}
		
		return $code;
	}
	
	
	/**
	 * Validate the authorisation code
	 * 
	 * @param string $code         The authorisation code
	 * @param string $client_id    The client ID
	 * @param string $redirect_uri The client redirect URI
	 * 
	 * @access public
	 * @return bool if the authorisation code is invalid, return object otherwise
	 */
	public function validate_auth_code($code = '', $client_id = '', $redirect_uri = '')
	{
		$validate = $this->ci->mongo_db
								->select(array('id', 'type_id'))
								->get_where('oauth_sessions', array(
									'client_id'		=> $client_id,
									'redirect_uri'	=> $redirect_uri, 
									'code'			=> $code
								));
		
		if (count($validate) === 0)
		{
			return FALSE;
		}
		
		else
		{
			return (object) $validate[0];
		}
	}
	
	/**
	 * Generates a new access token (or returns an existing one)
	 * 
	 * @param string $session_id The session ID number
	 * 
	 * @access public
	 * @return string
	 */
	public function get_access_token($session_id = '')
	{
		// Check if an access token exists already
		$exists_query = $this->ci->mongo_db
									->select('access_token')
									->where('_id', $session_id)
									->where_ne('access_token', NULL)
									->get('oauth_sessions');
		
		// If an access token already exists, return it and remove the authorization code
		if (count($exists_query) === 1)
		{
			// Remove the authorization code
			$this->ci->mongo_db
						->where(array('_id' => $session_id))
						->set(array(
							'code'	=>	NULL,
							'stage'	=>	'granted'
						))
						->update('oauth_sessions');
			
			// Return the access token
			$exists = (object) $exists_query[0];
			return $exists->access_token;
		}
		
		// An access token doesn't exist yet so create one and remove the authorization code
		else
		{
			$access_token = sha1(time().uniqid());
			
			$updates = array(
				'code'			=>	NULL,
				'access_token'	=>	$access_token,
				'last_updated'	=>	new MongoDate(strtotime('now')),
				'stage'			=>	'granted'
			);
						
			// Update the OAuth session
			$this->ci->mongo_db
						->where(array('_id' => new MongoId($session_id)))
						->set($updates)
						->update('oauth_sessions', $updates);
			
			// Update the session scopes with the access token
			$this->ci->mongo_db
						->where(array('session_id' => $session_id))
						->set(array('access_token'	=>	$access_token))
						->update('oauth_session_scopes');

			return $access_token;
		}
	}
		
	/**
	 * Validates an access token
	 * 
	 * @param string $access_token The access token
	 * @param array  $scopes       Scopes to validate the access token against
	 * 
	 * @access public
	 * @return void
	 */
	public function validate_access_token($access_token = '', $scopes = array())
	{
		// Validate the token exists
		$valid_token = $this->ci->mongo_db
									->where(array(
										'access_token'	=>	$access_token
									))
									->get('oauth_sessions');
		
		// The access token doesn't exists
		if (count($valid_token) === 0)
		{
			return FALSE;
		}

		// The access token does exist, validate each scope
		else
		{
			$token = (object) $valid_token[0];
		
			if (count($scopes) > 0)
			{
				foreach ($scopes as $scope)
				{
					$scope_exists = $this->ci->mongo_db
												->where(array(
													'access_token'	=>	$access_token,
													'scope'			=>	$scope
												))
												->count('oauth_session_scopes');
					
					if ($scope_exists === 0)
					{
						return FALSE;
					}
				}
				
				return TRUE;
			}
			
			else
			{
				return TRUE;
			}
		}
		
	}	
	
	/**
	 * Tests if a user has already authorized an application and an access token has been granted
	 * 
	 * @param string $user_id   The user ID
	 * @param string $client_id The client ID
	 * 
	 * @access public
	 * @return bool
	 */
	public function access_token_exists($user_id = '', $client_id = '')
	{
		$token_query = $this->ci->mongo_db
									->select('access_token')
									->where(array(
										'client_id'					=> $client_id,
										'type_id'					=> $user_id,
										'type'						=> 'user'))
									->where_ne('access_token', NULL)
									->get('oauth_sessions');
		
		if (count($token_query) === 1)
		{
			return (object) $token_query[0];
		}
		
		else
		{
			return FALSE;
		}
	}
	
	/**
	 * Tests if a scope exists in the database.
	 *
	 * @param string $scope The scope to be checked
	 * 
	 * @access public
	 * @return bool
	 */
	public function scope_exists($scope = '')
	{
		$exists = $this->ci->mongo_db
							->where('scope', $scope)
							->count('scopes');
		
		return ($exists === 1) ? TRUE : FALSE;
	}
	
	/**
	 * Returns details about a scope
	 * 
	 * @param mixed $scopes The scope(s) details to be returned
	 * 
	 * @access public
	 * @return object
	 */
	public function scope_details($scopes)
	{
		if (is_array($scopes))
		{
			$scope_details = $this->ci->mongo_db
									->where_in('scope', $scopes)
									->get('scopes');
		}
		
		else
		{
			$scope_details = $this->ci->mongo_db
									->where('scope', $scopes)
									->get('scopes');
		}
		
		$scopes = array();
		
		if (count($scope_details) > 0)
		{
			foreach ($scope_details as $detail)
			{
				$obj = (object) $detail;
				$scopes[] = array(
					'name' => $obj->name
					//,'description' => $obj->description
				);
			}
		}
		
		return $scopes;
	}
		
	/**
	 * Generates the redirect uri with appended params
	 * 
	 * @param string $redirect_uri    The redirect URI
	 * @param array  $params          The parameters to be appended to the URL
	 * @param string $query_delimeter The delimiter between the variables and the URL
	 * 
	 * @access public
	 * @return string
	 */
	public function redirect_uri($redirect_uri = '', $params = array(), $query_delimeter = '?')
	{
		if (strstr($redirect_uri, $query_delimeter))
		{
			$redirect_uri = $redirect_uri . '&' . http_build_query($params);
		}
		else
		{
			$redirect_uri = $redirect_uri . $query_delimeter . http_build_query($params);
		}
		
		return $redirect_uri;
	}
	
	/**
	 * Sign the user into your application.
	 *
	 * Edit this function to suit your needs. It must return a user's id as a string
	 * or FALSE if the sign in was incorrect
	 * 
	 * @param string $username The user's username
	 * @param string $password The user's password
	 * 
	 * @access public
	 * @return string|bool
	 */
	public function validate_user($username = '', $password = '')
	{
		$u = new User($username, $password);
		if($u instanceof User && $u->check_login())
		{ 
			return $u;
		}
		else
		{
			return false;
		}
		
	}
		
}

// END Oauth_server class

// End of file Oauth_server.php
// Location: ./application/libraries/Oauth_server.php
