<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * CodeIgniter MongoDB Session Driver Library
 *
 * The library adds a driver to the CodeIgniter Session Drivers.
 * It's uses CodeIgniter MongoDB Library by Erwin Houtsma as
 * MongoDB interface: https://github.com/ehoutsma/codeigniter-mongodb
 *
 * Installation:
 * - Place Session.php file in "application/libraries/Sessin/drivers" directory.
 *
 * - Place mongodb_session.php file in "application/config" directory.
 *
 * - Make sure that you have installed CodeIgniter MongoDB Library and your MongoDB
 *   connection parameters are correctly setup in "application/config/mongodb.php".
 *
 * - Make sure that "sess_driver" directive is set to 'mongodb' in
 *   "application/config/config.php" file.
 *
 *
 *
 * @package		CodeIgniter
 * @author		Erwin Houtsma <erwin@houtsmabedrijfsadvies.nl>
 * @copyright           Copyright (c) 2016 Erwin Houtsma.
 * @license		http://codeigniter.com/user_guide/license.html
 * @link		https://github.com/ehoutsma/codeigniter-session-mongodb-driver
 * @version             Version 1.0
 * @filesource
 */

// ------------------------------------------------------------------------

class CI_Session_mongodb_driver extends CI_Session_driver implements SessionHandlerInterface {

	/**
	 * Config directives array.
	 *
	 * @var array
	 * @access private
	 */
	protected $_config = array();

	/**
	 * Config filename.
	 *
	 * @var string
	 * @access private
	 */
	protected $_config_file = 'mongodb_session';

	/**
	 * Indicates whether to use mongodb as session database backend.
	 *
	 * @var boolean
	 * @access private
	 */
	protected $_use_mongodb;

	// --------------------------------------------------------------------

	/**
	 * Session Constructor
	 *
	 * The constructor runs the session routines automatically
	 * whenever the class is instantiated.
	 *
	 * For MongoDB, this loads custom config and MongoDB active record lib
	 */
	public function __construct(&$params)
	{
		parent::__construct($params);
                // Set the super object to a local variable for use throughout the class
		$this->CI =& get_instance();
                $this->CI->benchmark->mark('SESSION_start');

                // Load config directives
		$this->CI->config->load($this->_config_file);
                
		$config = $this->CI->config->item('default');
		$this->_config['sess_use_mongodb'] = $config['sess_use_mongodb'];

                $this->_config['sess_collection_name'] = $config['sess_collection_name'];

		$this->_use_mongodb = TRUE;

		// Set all the session preferences, which can either be set
		// manually via the $params array above or via the config file
		foreach (array('sess_encrypt_cookie', 'sess_use_database', 'sess_table_name', 'sess_expiration', 'sess_expire_on_close', 'sess_match_ip', 'sess_match_useragent', 'sess_cookie_name', 'cookie_path', 'cookie_domain', 'cookie_secure', 'sess_time_to_update', 'time_reference', 'cookie_prefix', 'encryption_key') as $key)
		{
			$this->$key = (isset($params[$key])) ? $params[$key] : $this->CI->config->item($key);
		}

                $this->CI->load->library('mongo_db');
		
		// Set the "now" time.  Can either be GMT or server time, based on the
		// config prefs.  We use this to set the "last activity" time
		$this->now = time();

		// Set the session length. If the session expiration is
		// set to zero we'll set the expiration two years from now.
		if ($this->sess_expiration == 0)
		{
			$this->sess_expiration = (60*60*24*365*2);
		}

		// Set the cookie name
		$this->sess_cookie_name = $this->cookie_prefix.$this->sess_cookie_name;
        }
        
        
        public function open($save_path, $name)
        {
                log_message('debug', "Session routines successfully run");

                return TRUE;
        }
        
	// --------------------------------------------------------------------

	/**
	 * Fetches the current session data if it exists
	 *
	 * @access	public
	 * @return	bool
         * 	 */
	public function read($session_id)
	{
		if ($this->_get_lock($session_id) !== FALSE)
		{
                    $this->_session_id = $session_id;

                    // Query mongodb to find possible session document
                    $current_session = $this->CI->mongo_db
                            ->where('id', $session_id);


                    if ($this->_config['match_ip'])
                    {
                            $this->CI->mongo_db->where('ip_address', $_SERVER['REMOTE_ADDR']);
                    }            
                    $result = $this->CI->mongo_db->get($this->_config['sess_collection_name']);
                    if (empty($result))
                    {
                            // PHP7 will reuse the same SessionHandler object after
                            // ID regeneration, so we need to explicitly set this to
                            // FALSE instead of relying on the default ...
                            $this->_row_exists = FALSE;
                            $this->_fingerprint = md5('');
                            return '';
                    }            
                    if (is_object($result)) 
                    {
                        $result = $result[0]->data;
                    } else {
                        $result = $result[0]->data;
                    }

                    $this->_fingerprint = md5($result);
                    $this->_row_exists = TRUE;
                    return $result;            
		}

		$this->_fingerprint = md5('');
		return '';
        }
        
	// --------------------------------------------------------------------

	/**
	 * Writes the session data
	 *
	 * @access	public
	 * @return	void
	 */
	public function write($session_id, $session_data)
	{
		if ($session_id !== $this->_session_id)
		{
			if ( ! $this->_release_lock() OR ! $this->_get_lock($session_id))
			{
				return FALSE;
			}

			$this->_row_exists = FALSE;
			$this->_session_id = $session_id;
		}
		elseif ($this->_lock === FALSE)
		{
			return FALSE;
		}
		if ($this->_row_exists === FALSE)
		{
			$insert_data = array(
				'id' => $session_id,
				'ip_address' => $_SERVER['REMOTE_ADDR'],
				'timestamp' => time(),
				'data' => $session_data
			);
                        error_reporting(E_ALL);
			$insertResult = ($this->CI->mongo_db
				->insert($this->_config['sess_collection_name'], $insert_data));
			{
				$this->_fingerprint = md5($session_data);
				return $this->_row_exists = TRUE;
			}

			return FALSE;
		}

		$this->CI->mongo_db->where('id', $session_id);
		if ($this->_config['match_ip'])
		{
			$this->CI->mongo_db->where('ip_address', $_SERVER['REMOTE_ADDR']);
		}

		$update_data = array('timestamp' => time());
		if ($this->_fingerprint !== md5($session_data))
		{
			$update_data['data'] = $session_data;
		}

		if ($this->CI->mongo_db->set($update_data)->update($this->_config['sess_collection_name']))
		{
			$this->_fingerprint = md5($session_data);
			return TRUE;
		}

		return FALSE;            
	}

        public function close()
        {
                // Free locks, close connections / streams / etc.
                $this->CI->benchmark->mark('SESSION_end');
                return TRUE;
        }        

	// --------------------------------------------------------------------

	/**
	 * Destroys the current session
	 *
	 * @access	public
	 * @return	void
	 */
	public function destroy($session_id)
	{
		if ($this->_lock)
		{
			$this->CI->mongo_db->where('id', $session_id);
			if ($this->_config['match_ip'])
			{
				$this->CI->mongo_db->where('ip_address', $_SERVER['REMOTE_ADDR']);
			}

			return $this->CI->mongo_db->delete($this->_config['sess_collection_name'])
				? ($this->close() && $this->_cookie_destroy())
				: FALSE;
		}

		return ($this->close() && $this->_cookie_destroy());
	}

	// --------------------------------------------------------------------

	/**
	 * Garbage collection helper
	 *
	 * This deletes expired session rows from database
	 * if the probability percentage is met
	 *
	 * @access	public
	 * @return	void
	 */
	public function gc($maxlifetime)
	{
            $result = $this->CI->mongo_db->where_lt('timestamp', (time() - $maxlifetime))->delete_all($this->_config['sess_collection_name']);
            return $result;
	}

	protected function _get_lock($session_id) {
            return parent::_get_lock($session_id);
        }
        
	protected function _release_lock() {
            return parent::_release_lock($session_id);
        }
        
}
// END Session_mongodb_driver Class

/* End of file CI_Session_mongodb_driver.php */
/* Location: ./application/libraries/Session/drivers/CI_Session_mongodb_driver.php */