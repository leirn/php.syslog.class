<?php
/**
 *
 * Description
 *
 *   The Syslog class is a syslog client implementation in PHP
 *   following the RFC 3164, 5424, 5425, 5426 rules.
 *   This class is compatible with PHP logger constants for serverity and facility.
 *
 *   Default value are UDP connection with RFC3164 mode.
 *
 *   Facility values:
 *      LOG_KERN		kernel messages
 *      LOG_USER		user-level messages
 *      LOG_MAIL		mail system
 *      LOG_DAEMON	system daemons
 *      LOG_AUTH		security/authorization messages
 *      LOG_SYSLOG		messages generated internally by syslogd
 *      LOG_LPR		line printer subsystem
 *      LOG_NEWS		network news subsystem
 *      LOG_UUCP		UUCP subsystem
 *      LOG_CRON		clock daemon
 *      LOG_AUTHPRIV 	security/authorization messages
 *      LOG_FTP 		FTP daemon
 *      LOG_NTP		NTP subsystem
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
 *     LOG_ERR 		Error: error conditions
 *     LOG_WARNING 	Warning: warning conditions
 *     LOG_NOTICE 		Notice: normal but significant condition (default value)
 *     LOG_INFO 		Informational: informational messages
 *     LOG_DEBUG 		Debug: debug-level messages
 *
 *   Protocols:
 *     SYSLOG_UDP		udp protocol. Defaut behaviour
 *     SYSLOG_TCP		tcp protocol
 *     SYSLOG_SSL		ssl protocol. CA File can optionnaly be set 
 *     SYSLOG_TLS		tls protocol
 *
 *
 * Usage
 *
 *   require_once('syslog.class.php');
 *   $syslog = new Syslog($hostname = "", $appname = LOG_NILVALUE, $protocol  = SYSLOG_UDP, $_procid = LOG_NILVALUE);
 *   $syslog->logger($priority = LOG_LOCAL0 + LOG_NOTICE, $content = "");
 *      or
 *  $syslog->logger542X($priority = 133, $content = "Default content", $msgid = "-", $structured_data = "-");
 *      or
 *  $syslog->logger3164($priority = 133, $content = "Default content");
 *
 * Examples
 *
 *   Example 1
 *
 *         require_once('syslog.class.php');
 *         $syslog = new Syslog();
 *         $syslog->logger(LOG_LOCAL0 + LOG_NOTICE, 'Syslog message');
 *
 *
 *   Example 2
 *
 *         require_once('syslog.class.php');
 *         $syslog = new Syslog('myserver', 'MyApp', SYSLOG_TCP);
 *         $syslog->logger(LOG_LOCAL0 + LOG_NOTICE, 'Syslog message');
 * 
 *
 *   Example 3
 *
 *         require_once('syslog.class.php');
 *         $syslog = new Syslog();
 *         $syslog->setHostname('myserver');
 *         $syslog->setRFC(SYSLOG_RFC542X);
 *         $syslog->setAppname('MyApp');
 *         $syslog->setServer('192.168.0.12');
 *         $syslog->logger(LOG_LOCAL0 + LOG_NOTICE, 'Syslog message');
 *
 *   Example 4
 *
 *         require_once('syslog.class.php');
 *         $syslog = new Syslog("myserver", "MyApp", SYSLOG_SSL);
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
 * Licence
 *
 *   Copyright 2013 Laurent Vromman
 *   
 *      This program is free software: you can redistribute it and/or modify
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
 * TODO : RFC 5848, RFC 6587, Permanent socket
 *
 */
 
define("LOG_LINUX_NETWORD_INTERFACE", "eth0");
define("LOG_NILVALUE", "-");

define("LOG_FTP", 88);
define("LOG_NTP", 96);
define("LOG_LOG_AUDIT", 104);
define("LOG_ALERT", 112);
define("LOG_CLOCK", 120);

define("SYSLOG_TCP", "tcp");
define("SYSLOG_UDP", "udp");
define("SYSLOG_SSL", "ssl");
define("SYSLOG_TLS", "tls");
// Compatibility for RFC 5424, 5425 and 5426
define("SYSLOG_RFC542X", 1);
define("SYSLOG_RFC3164", 0);
 
class Syslog
{
    private $_hostname; // no embedded space, no domain name, only a-z A-Z 0-9 and other authorized characters
    private $_server;    // Syslog destination server
    private $_port;       // Standard syslog port is 514 or 6514 for RFC 5425 (TLS)
    private $_protocol;  // Allow to specify between udp, tcp, ssl and tls
    private $_socket;
    private $_cafile;
    private $_procid;
    private $_appname;

    public function Syslog($hostname = "", $appname = LOG_NILVALUE,
    	$protocol  = SYSLOG_UDP, $procid = LOG_NILVALUE
    ) {
        $this->_rfc = SYSLOG_RFC3164;
        $this->_socket = FALSE;
        $this->_server   = '127.0.0.1';
        $this->setProcid($procid);

        $this->setAppname($appname);

        $this->_hostname = $hostname;
        if (strlen($hostname) == 0) {
            if (isset($_SERVER["SERVER_NAME"])) {
                $hostname = $_SERVER["SERVER_NAME"];
                if($this->_rfc == SYSLOG_RFC3164)
                    $hostname = substr($hostname, 0, strpos($hostname.".", "."));
            }
            elseif (isset($_SERVER["SERVER_ADDR"])) {
                $hostname = $_SERVER["SERVER_ADDR"];
            }
            else {
                if($this->_rfc == SYSLOG_RFC3164)
                    $hostname = "server";
                else
                    $hostname = LOG_NILVALUE;
            }
        }
        $this->setHostname($hostname);

        $this->setProtocol($protocol);
        if (!in_array($this->_protocol, array(SYSLOG_UDP, SYSLOG_TCP, SYSLOG_SSL, SYSLOG_TLS))) {
            $this->_protocol = SYSLOG_UDP;
        }
        // RFC5425
        if($this->_protocol == SYSLOG_TLS)
            $this->_port = 6514;
        else
            $this->_port  = 514;
    }

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
                $ifconfig = shell_exec('/sbin/ifconfig '.LOG_LINUX_NETWORD_INTERFACE);
                preg_match('/addr:([\d\.]+)/', $ifconfig, $match);
                return $match[1];
            }
        }
    }

    public function setRFC($rfc)
    {
        $this->_rfc = $rfc;
    }

    public function setHostname($hostname)
    {
        $this->_hostname = substr($hostname, 0, 255);
        if(strlen($this->_hostname) == 0) $this->_hostname = LOG_NILVALUE;
    }

    public function setServer($server)
    {
        $this->_server = $server;
    }

    public function setPort($port)
    {
        if ((intval($port) > 0) && (intval($port) < 65536)) {
        $this->_port = intval($port);
        }
    }

    public function setProtocol($protocol)
    {
        if (in_array($protocol, array(SYSLOG_UDP, SYSLOG_TCP, SYSLOG_SSL, SYSLOG_TLS))) {
            $this->_protocol = $protocol;
        }
    }

    public function setCAFile($cafile)
    {
        $this->_cafile = $cafile;
    }

    public function setProcid($procid)
    {
        $this->_procid  = substr($procid, 0, 128);
        if(strlen($this->_procid) == 0) $this->_procid = LOG_NILVALUE;
    }

    public function setAppname($appname)
    {
        $this->_appname = substr($appname, 0, 48);
        if(strlen($this->_appname) == 0) $this->_appname = LOG_NILVALUE;
    }
        
    private function openSocket ()
    {
        if ($this->_socket)
            $this->closeSocket();
        $contextOptions = array();;
        
        if($this->_protocol == SYSLOG_SSL && $this->_cafile != NULL) {
            //http://php.net/manual/en/context.ssl.php
            $contextOptions = array(
                'ssl' => array(
                    'cafile'        => $this->_cafile
                    )
            );
        }
        $sslContext = stream_context_create($contextOptions);
        
        $this->_socket = stream_socket_client($this->_protocol."://".$this->_server.":".$this->_port, $errno, $errstr, ini_get("default_socket_timeout"), STREAM_CLIENT_CONNECT, $sslContext);
        
        if (!$this->_socket) {
            throw new Exception("ERROR: $errno - $errstr");
        }
    }
	
    private function closeSocket ()
    {
        fclose($this->_socket);
        $this->_socket = NULL;
    }
        
    public function logger3164($priority = 133, $content = "Default content")
    {
        $rfc = $this->_rfc;
        $this->_rfc = SYSLOG_RFC3164;
        $this->logger($priority, $content);
        $this->_rfc = $rfc;
    }
        
    public function logger542X($priority = 133, $content = "Default content",
    	$msgid = "-", $structured_data = "-"
    ) {
        $rfc = $this->_rfc;
        $this->_rfc = SYSLOG_RFC542X;
        $this->logger($priority, $content, $msgid = "-", $structured_data);
        $this->_rfc = $rfc;
    }
	
    public function logger($priority = 133, $content = "Default content",
    	$msgid = "-", $structured_data = "-"
    ) {
        $this->_content = $content;
        
        if(strlen($msgid) == 0) $msgid = LOG_NILVALUE;
        if(strlen($structured_data) == 0) $structured_data = LOG_NILVALUE;
        
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
        if($this->_rfc == SYSLOG_RFC542X) {
            $timestamp = date("c");
            $syslog_version = "1 ";
        }
        else {
            $actualtime = time();
            $timestamp  = date("M ", $actualtime).substr(date(" j", $actualtime), -2).date(" H:i:s", $actualtime);
            $syslog_version = "";
        }
        $header = $pri.$syslog_version.$timestamp." ".$this->_hostname." ";
        if($this->_rfc == SYSLOG_RFC542X) {
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
            if($this->_rfc == SYSLOG_RFC542X && $this->protocol == SYSLOG_TLS) {
                $message = strlen($message)." ".$message;
        }
        
        fwrite($this->_socket, $message);
        
        $this->closeSocket();   
    }
}
?>
