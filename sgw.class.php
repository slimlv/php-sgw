<?php

/*
 * SGW processor for Swedbank SGW service able to
 * # send task to SGW
 * # fetch task from SGW
 * # purge task from SGW
 *
 * Author: Deniss Gaplevsky slim@inbox.lv
 *
 */

class SGW {
  
   private $gw_ok_header = 'X-Gateway-Message';
   private $gw_header_CorrelationID = 'CorrelationID';
   private $gw_header_RequestId = 'RequestId';
   private $gw_header_TrackingID = 'TrackingID';
   private $key_pass = '';

   public  $gw = 'https://dev.hansagateway.net';
   public  $keyfile = null;
   public  $certfile = null;
   public  $transport_cert = null;
   public  $status = null;
   public  $errors = array();
   public  $debug = array();

   function  __construct($keyfile = null, $certfile = null) {
        if ($keyfile) $this->keyfile = $keyfile;
        if ($certfile) $this->certfile = $certfile;
   }

   function setKeyCert($keyfile,$certfile) {
        $this->keyfile = $keyfile;
        $this->certfile = $certfile;
   }

  function setKeyPass($key_pass = null) {
    if ($key_pass) {
        if (!$this->keyfile) throw new Exception('keyfile is not set');
        $res = openssl_pkey_get_private('file://'.$this->keyfile, $key_pass);
        if (!$res) throw new Exception('passphrase is not valid for ',$this->keyfile);
        $this->key_pass = $key_pass;
        openssl_pkey_free($res);
    } else {
    	throw new Exception('passphrase is empty');
    }
  }

   function send($task) {
        $this->errors = array();
        if (empty($task->inputCDOC)) throw new Exception('CDOC is not set');

        list($code, $headers, $body) = $this->callCurl('PUT',$task->inputCDOC, [ $this->gw_header_CorrelationID.': '.$task->CorrelationID]);
        if ( $code == '500' ) throw new Exception('error 500: '.$headers.$body);
        if ($headers[$this->gw_ok_header] != '1')  throw new Exception('No '.$this->gw_ok_header.' in output set: '.print_r($headers,1));
        if (empty($headers[$this->gw_header_RequestId]))  throw new Exception('No '.$this->gw_header_RequestId.' in output set: '.print_r($headers,1));
        $task->RequestId = $headers[$this->gw_header_RequestId];
        return true;
   }

   function receive($task) {
      	$this->errors = array();
        list($code, $headers,$body) = $this->callCurl('GET');
        if ( $code == '500' || $code == '400' )  throw new Exception('error '.$code.': '.$headers.$body);

        if ( $code == '404' ) {
            $this->errors[] = 'code '.$code.' No messages: '.print_r($headers,1).$body;
            return null;
        }

        $task->CorrelationID = $headers[$this->gw_header_CorrelationID]; 
        $task->outputCDOC = $body;
        $task->TrackingID = $headers[$this->gw_header_TrackingID];
        return true;
   }

    function purge($task) {
        $this->errors = array();
   	    if ( empty($task->TrackingID) ) return false;
        $this->callCurl('DELETE', '', [ $this->gw_header_TrackingID.': '.$task->TrackingID ]);
	    return true;
   }

   function getError() { return implode("\r\n",$this->errors); }


   private function callCurl($method, $content = null, $headers = array()) {

    	$this->debug[] = "callCurl($method, $content)";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->gw);
        curl_setopt($ch, CURLOPT_HEADER, 1); # to include the header in the output
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); # to return the transfer as a string of the return value of curl_exec() instead of outputting it out directly
        curl_setopt($ch, CURLOPT_CERTINFO, 1); # to output SSL certification information to STDERR on secure transfers
        curl_setopt($ch, CURLOPT_SSLCERT, $this->certfile); #  The name of a file containing a PEM formatted certificate.
        curl_setopt($ch, CURLOPT_SSLKEY, $this->keyfile); # The name of a file containing a private SSL key.
        if ($this->key_pass) curl_setopt($ch, CURLOPT_SSLKEYPASSWD, $this->key_pass);
        curl_setopt($ch, CURLINFO_HEADER_OUT, 1); # to track the handle's request string

        
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->transport_cert ? 1 : 0 ); #FALSE to stop cURL from verifying the peer's certificate. 

        if ($this->transport_cert) {
            curl_setopt($ch, CURLOPT_CAINFO, $this->transport_cert ); # The name of a file holding one or more certificates to verify the peer with
        }

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);

        if ( $method != 'GET') {
            curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge(array('Content-Length: ' . strlen($content),'Expect:'), $headers) ); 
            curl_setopt($ch, CURLOPT_POSTFIELDS, $content);
        }

        $response = curl_exec($ch);
        if ($response === false )  throw new Exception('curl error: '.curl_error($ch));
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    	$this->debug[] = 'CURL headers send: '. curl_getinfo($ch,CURLINFO_HEADER_OUT);
        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        $header = substr($response, 0, $header_size);
        $body = substr($response, $header_size);

        $_headers = explode("\n",$header);
        $headers = array();
        foreach ($_headers as $header) {
           if ( strpos($header,':') === false ) continue;
           list($key,$val) = explode(':',$header);
           $headers[trim($key)] = trim($val);
        }

        $this->debug[] = "curl_exec: ".$response;
        $this->debug[] = "headers: ".print_r($headers,1);

        return [$code, $headers,$body];
   }

}
