<?php
/**
 *   The Syslog class is a syslog client implementation in PHP
 *   following the RFC 3164, 5424, 5425, 5426 rules.
 *   This class is compatible with PHP logger constants for severity and facility.
 *   Default value are UDP connection with RFC3164 mode
 * 
 *  Facility values:
 *      LOG_KERN		kernel messages
 *      LOG_USER		user-level messages
 *      LOG_MAIL		mail system
 *      LOG_DAEMON	    system daemons
 *      LOG_AUTH		security/authorization messages
 *      LOG_SYSLOG		messages generated internally by syslogd
 *      LOG_LPR		    line printer subsystem
 *      LOG_NEWS		network news subsystem
 *      LOG_UUCP		UUCP subsystem
 *      LOG_CRON		clock daemon
 *      LOG_AUTHPRIV 	security/authorization messages
 *      LOG_FTP 		FTP daemon
 *      LOG_NTP		    NTP subsystem
 *      LOG_AUDIT 		log audit
 *      LOG_LOG_ALERT 	log alert
 *      LOG_CLOCK 		clock daemon
 *      LOG_LOCAL0 		local user 0 (local0) (default value)
 *      LOG_LOCAL1 		local user 1 (local1)
 *      LOG_LOCAL2 		local user 2 (local2)
 *      LOG_LOCAL3 		local user 3 (local3)
 *      LOG_LOCAL4 		local user 4 (local4)
 *      LOG_LOCAL5 		local user 5 (local5)
 *      LOG_LOCAL6 		local user 6 (local6)
 *      LOG_LOCAL7 		local user 7 (local7)
 *
 *   Severity values:
 *     LOG_EMERG 		Emergency: system is unusable
 *     LOG_ALERT 		Alert: action must be taken immediately
 *     LOG_CRIT 		Critical: critical conditions
 *     LOG_ERR 		    Error: error conditions
 *     LOG_WARNING 	    Warning: warning conditions
 *     LOG_NOTICE 		Notice: normal but significant condition (default value)
 *     LOG_INFO 		Informational: informational messages
 *     LOG_DEBUG 		Debug: debug-level messages
 *
 *   Protocols:
 *     NET_SYSLOG_UDP		udp protocol. Defaut behaviour
 *     NET_SYSLOG_TCP		tcp protocol
 *     NET_SYSLOG_SSL		ssl protocol. CA File can optionnaly be set 
 *     NET_SYSLOG_TLS		tls protocol
 *
 *
 * Usage
 *
 *   require_once('syslog.class.php');
 *   $syslog = new Net_Syslog($hostname = "", $appname = NET_SYSLOG_NILVALUE,
 *    $protocol  = NET_SYSLOG_UDP, $_procid = NET_SYSLOG_NILVALUE);
 *   $syslog->logger($priority = LOG_LOCAL0 + LOG_NOTICE, $content = "");
 *      or
 *  $syslog->logger542X($priority = 133, $content = "Default content", 
 *      $msgid = NET_SYSLOG_NILVALUE, $structured_data = NET_SYSLOG_NILVALUE);
 *      or
 *  $syslog->logger3164($priority = 133, $content = "Default content");
 *
 * Examples
 *
 *   Example 1
 *
 *         require_once('syslog.class.php');
 *         $syslog = new Net_Syslog();
 *         $syslog->logger(LOG_LOCAL0 + LOG_NOTICE, 'Syslog message');
 *
 *
 *   Example 2
 *
 *         require_once('syslog.class.php');
 *         $syslog = new Net_Syslog('myserver', 'MyApp', NET_SYSLOG_TCP);
 *         $syslog->logger(LOG_LOCAL0 + LOG_NOTICE, 'Syslog message');
 * 
 *
 *   Example 3
 *
 *         require_once('syslog.class.php');
 *         $syslog = new Net_Syslog();
 *         $syslog->setHostname('myserver');
 *         $syslog->setRFC(NET_SYSLOG_RFC542X);
 *         $syslog->setAppname('MyApp');
 *         $syslog->setServer('192.168.0.12');
 *         $syslog->logger(LOG_LOCAL0 + LOG_NOTICE, 'Syslog message');
 *
 *   Example 4
 *
 *         require_once('syslog.class.php');
 *         $syslog = new Net_Syslog("myserver", "MyApp", NET_SYSLOG_SSL);
 *         $syslog->setCAFile("ca.crt");
 *         $syslog->logger(LOG_CRON + LOG_NOTICE, "Syslog message");
 *
 * Prerequisites
 *
 *   - Sockets support must be enabled.
 *     * In Linux and *nix environments, the extension is enabled at
 *       compile time using the --enable-sockets configure option
 *     * In Windows, PHP Sockets can be activated by un-commenting
 *       extension=php_sockets.dll in php.ini
 *
 *
 * TODO : RFC 5848, RFC 6587, Permanent socket
 *
 * PHP version 5
 *
 * LICENSE:
 *   
 *       This program is free software: you can redistribute it and/or modify
 *       it under the terms of the   GNU LesserGeneral Public License as published by
 *       the Free Software Foundation, either version 3 of the License, or
 *       (at your option) any later version.
 *   
 *       This program is distributed in the hope that it will be useful,
 *       but WITHOUT ANY WARRANTY; without even the implied warranty of
 *       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *       GNU Lesser General Public License for more details.
 *   
 *       You should have received a copy of the GNU General Public License
 *       along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @category  Networking
 * @package   Net_Syslog
 * @author    Laurent Vromman <laurent@vromman.org>
 * @copyright 2013 Laurent Vromman
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 3
 * @link      http://pear.php.net/package/Net_Syslog
 */


// {{{ constants

/**
 * Set default linux network interface
 */
define("NET_SYSLOG_LINUX_NETWORD_INTERFACE", "eth0");

/**
 * Set NILVALUE as defined in RFC 5424
 */
define("NET_SYSLOG_NILVALUE", "-");

/**
 * Add missing LOG_FTP level log to existing PHP log levels
 */
defined('LOG_FTP') or define("LOG_FTP", 88);


/**
 * Add missing LOG_NTP level log to existing PHP log levels
 */
defined('LOG_NTP') or define("LOG_NTP", 96);


/**
 * Add missing LOG_LOG_AUDIT level log to existing PHP log levels
 */
defined('LOG_LOG_AUDIT') or define("LOG_LOG_AUDIT", 104);


/**
 * Add missing LOG_ALERT level log to existing PHP log levels
 */
defined('LOG_ALERT') or define("LOG_ALERT", 112);


/**
 * Add missing LOG_CLOCK level log to existing PHP log levels
 */
defined('LOG_CLOCK') or define("LOG_CLOCK", 120);

/**
 * TCP connection mode
 */
define("NET_SYSLOG_TCP", "tcp");

/**
 * UDP connection mode
 */
define("NET_SYSLOG_UDP", "udp");

/**
 * SSL connection mode
 */
define("NET_SYSLOG_SSL", "ssl");

/**
 * TLS connection mode
 */
define("NET_SYSLOG_TLS", "tls");

/**
 * Compatibility for RFC 5424, 5425 and 5426
 */
define("NET_SYSLOG_RFC542X", 1);

/**
 * Compatibility for RFC 3164
 */
define("NET_SYSLOG_RFC3164", 0);
// }}}

/**
 * Short description for class
 *
 * Long description for class (if any)...
 *
 * @category   Networking
 * @package    Net_Syslog
 * @author     Laurent Vromman <laurent@vromman.org>
 * @copyright  2013 Laurent Vromman
 * @license    http://www.gnu.org/copyleft/lesser.html  LGPL License 3
 * @version    SVN: $Id$
 * @link       http://pear.php.net/package/Net_Syslog
 */
class Net_Syslog
{
    /**
     * Sender hostname
     * 
     * No domain name, only a-z A-Z 0-9 and other authorized characters
     * 
     * @access private
     * @var string
     */
    private $_hostname;

    /**
     * Syslog remote server address
     * 
     * @access private
     * @var string
     */
    private $_server;

    /**
     * Syslog remote server port
     * 
     * Standard syslog port is 514 or 6514 for RFC 5425 (TLS)
     * 
     * @access private
     * @var integer
     */
    private $_port;

    /**
     * Protocol to syslog server
     * 
     * Allowed values are :
     *  - NET_SYSLOG_UDP : UDP
     *  - NET_SYSLOG_TCP : TCP
     *  - NET_SYSLOG_SSL : SSL
     *  - NET_SYSLOG_TLS : TLS
     * 
     * @access private
     * @var string
     */
    private $_protocol;

    /**
     * Socket used by class
     * 
     * @access private
     * @var object
     */
    private $_socket;

    /**
     * filename for CA Certificate used in SSL connection, if necessary
     * 
     * @access private
     * @var string
     */
    private $_cafile;

    /**
     * ProcID as defined in RFC 5424
     * 
     * @access private
     * @var string
     */
    private $_procid;

    /**
     * AppName as defined in RFC 5424
     * 
     * @access private
     * @var string
     */
    private $_appname;

    /**
     * Constructor of class
     * 
     * @param string $hostname         Optional. Sender hostname.
     * @param string $appname          Optional. AppName as defined in RFC 5424.
     * @param string $protocol         Optional. Can be NET_SYSLOG_UDP, NET_SYSLOG_TCP, NET_SYSLOG_SSL or NET_SYSLOG_TLS.
     * @param string $procid           Optional. ProcID as defined in RFC 5424.
     * 
     * @access public
     * @see Net_Syslog
     */
    public function __construct($hostname = "", $appname = NET_SYSLOG_NILVALUE,
    	$protocol  = NET_SYSLOG_UDP, $procid = NET_SYSLOG_NILVALUE
    ) {
        $this->_rfc = NET_SYSLOG_RFC3164;
        $this->_socket = FALSE;
        $this->_server   = '127.0.0.1';
        $this->setProcid($procid);

        $this->setAppname($appname);

        $this->_hostname = $hostname;
        if (strlen($hostname) == 0) {
            if (isset($_SERVER["SERVER_NAME"])) {
                $hostname = $_SERVER["SERVER_NAME"];
                if($this->_rfc == NET_SYSLOG_RFC3164)
                    $hostname = substr($hostname, 0, strpos($hostname.".", "."));
            }
            elseif (isset($_SERVER["SERVER_ADDR"])) {
                $hostname = $_SERVER["SERVER_ADDR"];
            }
            else {
                if($this->_rfc == NET_SYSLOG_RFC3164)
                    $hostname = "server";
                else
                    $hostname = NET_SYSLOG_NILVALUE;
            }
        }
        $this->setHostname($hostname);

        $this->setProtocol($protocol);
        if (!in_array($this->_protocol, 
            array(NET_SYSLOG_UDP, NET_SYSLOG_TCP, NET_SYSLOG_SSL, NET_SYSLOG_TLS)
            )
        ) {
            $this->_protocol = NET_SYSLOG_UDP;
        }
        // RFC5425
        if($this->_protocol == NET_SYSLOG_TLS)
            $this->_port = 6514;
        else
            $this->_port  = 514;
    }

    /**
     * Function to get local server address when not available
     * 
     * @return string    Local server address
     * 
     * @access private
     */
    private function getServerAddress()
    {
        if(array_key_exists('SERVER_ADDR', $_SERVER))
            return $_SERVER['SERVER_ADDR'];
        elseif(array_key_exists('LOCAL_ADDR', $_SERVER))
            return $_SERVER['LOCAL_ADDR'];
        else {
            // Running CLI
            if(stristr(PHP_OS, 'WIN')) {
                return gethostbyname(php_uname("n"));
            }
            else {
                $ifconfig = shell_exec('/sbin/ifconfig '.NET_SYSLOG_LINUX_NETWORD_INTERFACE);
                preg_match('/addr:([\d\.]+)/', $ifconfig, $match);
                return $match[1];
            }
        }
    }

    /**
     * RFC Mode setter
     * 
     * @param int    $rfc The RFC mode. Can be NET_SYSLOG_RFC542X or NET_SYSLOG_RFC3164
     * 
     * @access public
     */
    public function setRFC($rfc)
    {
        $this->_rfc = $rfc;
    }

    /**
     * Sender hostname setter
     * 
     * @param string    $hostname No domain name, only a-z A-Z 0-9 and other authorized characters
     * 
     * @access public
     */
    public function setHostname($hostname)
    {
        $this->_hostname = substr($hostname, 0, 255);
        if(strlen($this->_hostname) == 0) $this->_hostname = NET_SYSLOG_NILVALUE;
    }

    /**
     * Remote server address setter
     * 
     * @param string    $server Can be an ip or a network name
     * 
     * @access public
     */
    public function setServer($server)
    {
        $this->_server = $server;
    }

    /**
     * Remote server port setter
     * 
     * @param int      $port TCP or UDP port on the remote syslog server
     * 
     * @access public
     */
    public function setPort($port)
    {
        if ((intval($port) > 0) && (intval($port) < 65536)) {
        $this->_port = intval($port);
        }
    }

    /**
     * Protocol setter
     * 
     * @param string   $protocol Can be NET_SYSLOG_UDP, NET_SYSLOG_TCP, NET_SYSLOG_SSL or NET_SYSLOG_TLS
     * 
     * @access public
     */
    public function setProtocol($protocol)
    {
        if (in_array($protocol, array(NET_SYSLOG_UDP, NET_SYSLOG_TCP, NET_SYSLOG_SSL, NET_SYSLOG_TLS))) {
            $this->_protocol = $protocol;
        }
    }

    /**
     * CA File setter
     * 
     * @param string   $cafile Filename for CA Certificate used in SSL connection, if necessary
     * 
     * @access public
     */
    public function setCAFile($cafile)
    {
        $this->_cafile = $cafile;
    }

    /**
     * ProcID setter
     * 
     * @param string   $procid ProcID as defined in RFC 5424
     * 
     * @access public
     */
    public function setProcid($procid)
    {
        $this->_procid  = substr($procid, 0, 128);
        if(strlen($this->_procid) == 0) $this->_procid = NET_SYSLOG_NILVALUE;
    }

    /**
     * AppName setter
     * 
     * @param string   $appname AppName as defined in RFC 5424
     * 
     * @access public
     */
    public function setAppname($appname)
    {
        $this->_appname = substr($appname, 0, 48);
        if(strlen($this->_appname) == 0) $this->_appname = NET_SYSLOG_NILVALUE;
    }
        
    /**
     * Open the socket to connect to the remote syslog server
     * 
     * @access private
     */
    private function openSocket ()
    {
        if ($this->_socket)
            $this->closeSocket();
        $contextOptions = array();;
        
        if($this->_protocol == NET_SYSLOG_SSL && $this->_cafile != NULL) {
            //http://php.net/manual/en/context.ssl.php
            $contextOptions = array(
                'ssl' => array(
                    'cafile'        => $this->_cafile
                    )
            );
        }
        $sslContext = stream_context_create($contextOptions);
        
        $this->_socket = stream_socket_client(
            $this->_protocol."://".$this->_server.":".$this->_port, 
            $errno, 
            $errstr, 
            ini_get("default_socket_timeout"), 
            STREAM_CLIENT_CONNECT, 
            $sslContext);
        
        if (!$this->_socket) {
            throw new Exception("ERROR: $errno - $errstr");
        }
    }
	
    /**
     * Close the socket to the remote syslog server
     * 
     * @access private
     */
    private function closeSocket ()
    {
        fclose($this->_socket);
        $this->_socket = NULL;
    }
        
    /**
     * Function to send a log message RFC3164 compliant
     * 
     * @param int    $priority Optional. Priority of message. Is a sum of Severity and Criticity.
     * @param string $content  Optional. Message content.
     * 
     * @access public
     * @see Net_Syslog
     */
    public function logger3164($priority = 133, $content = "Default content")
    {
        $rfc = $this->_rfc;
        $this->_rfc = NET_SYSLOG_RFC3164;
        $this->logger($priority, $content);
        $this->_rfc = $rfc;
    }
        
    /**
     * Function to send a log message RFC542X compliant
     * 
     * @param int    $priority         Optional. Priority of message. Is a sum of Severity and Criticity.
     * @param string $content          Optional. Message content.
     * @param string $msgid            Optional. MsgID of the message, according to RFC5424.
     * @param string $structured_data  Optional. Structured data of the message, according to RFC5424.
     * 
     * @access public
     * @see Net_Syslog
     */
    public function logger542X($priority = 133, $content = "Default content",
    	$msgid = "-", $structured_data = "-"
    ) {
        $rfc = $this->_rfc;
        $this->_rfc = NET_SYSLOG_RFC542X;
        $this->logger($priority, $content, $msgid = "-", $structured_data);
        $this->_rfc = $rfc;
    }
	
    /**
     * Function to send a log message. RFC3164 or 542X chosen according to $_rfc parameter.
     * 
     * @param int    $priority         Optional. Priority of message. Is a sum of Severity and Criticity.
     * @param string $content          Optional. Message content.
     * @param string $msgid            Optional. MsgID of the message, according to RFC5424. Ignored in RFC3164 mode.
     * @param string $structured_data  Optional. Structured data of the message, according to RFC5424. Ignored in RFC3164 mode.
     * 
     * @access public
     * @see Net_Syslog
     */
    public function logger($priority = 133, $content = "Default content",
    	$msgid = "-", $structured_data = "-"
    ) {
        $this->_content = $content;
        
        if(strlen($msgid) == 0) $msgid = NET_SYSLOG_NILVALUE;
        if(strlen($structured_data) == 0) $structured_data = NET_SYSLOG_NILVALUE;
        
        $facility = floor($priority/8);
        $severity = $priority - $facility * 8;
        if (0 > $severity || $severity > 7) { 
            throw new Exception("ERROR: unrecognized severity value : $severity");
        }
        
        if (0 > $facility || $facility > 23) { 
            throw new Exception("ERROR: unrecognized facility value : $facility");
        }
        
        $timestamp = date("c");
        
        $pri    = "<$priority>";
        if($this->_rfc == NET_SYSLOG_RFC542X) {
            $timestamp = date("c");
            $syslog_version = "1 ";
        }
        else {
            $actualtime = time();
            $timestamp  = date("M ", $actualtime)
                .substr(date(" j", $actualtime), -2)
                .date(" H:i:s", $actualtime);
            $syslog_version = "";
        }
        $header = $pri.$syslog_version.$timestamp." ".$this->_hostname." ";
        if($this->_rfc == NET_SYSLOG_RFC542X) {
            $header .= $this->_appname." ".$this->_procid." ".substr($msgid, 0, 32);
            $message = $header. " ".$structured_data." ".$content;
        }
        else {
            // RFC 3164 : Tagname max len : 32
            // RFC 3164 : Message max len : 1024
            if(strlen($this->_appname) > 0)
                $tag = substr($this->_appname, 0 , 32).": ";
                $message = substr($header.$tag.$content, 0, 1024);
            }
            
            $this->openSocket();
            
            // RFC 5425
            if($this->_rfc == NET_SYSLOG_RFC542X && $this->_protocol == NET_SYSLOG_TLS) {
                $message = strlen($message)." ".$message;
        }
        
        fwrite($this->_socket, $message);
        
        $this->closeSocket();   
    }
}
?>
