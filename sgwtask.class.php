<?php

/*
 * SGWTask class for Swedbank SGW service able to
 * # create signed bdoc
 * # encrypt to cdoc 
 * # decrypt cdoc
 * # extract file from bdoc
 *
 * Author: Deniss Gaplevsky slim@inbox.lv
 *
 */

class SGWTask {

  private $errors = array();
  private $keyfile = null;
  private $key_pass = '';
  private $certfile = null;
  private $sgw_certfile = null;

  public $inputXML = null;
  public $inputBDOC = null;
  public $inputCDOC = null;

  public $outputXML = null;
  public $outputBDOC = null;
  public $outputCDOC = null;

  public $CorrelationID = null; # set by client
  public $RequestId = null; # set by server
  public $TrackingID = null; # set by server, another header

  public $tmpdir = '/tmp/';

  const LIBNAME = 'php-sgw';
  const LIBVER  = 1.1;

  function  __construct($keyfile = null, $certfile = null, $sgw_certfile = null) {
    if ($keyfile) $this->keyfile = $keyfile;
    if ($certfile) $this->certfile = $certfile;
    if ($sgw_certfile) $this->sgw_certfile = $sgw_certfile;
  }    

  function setKeyPass($key_pass = null) {
    if ($key_pass) { 
        if (!$this->keyfile) throw new Exception('keyfile is not set');
        $res = openssl_pkey_get_private('file://'.$this->keyfile, $key_pass); 
        if (!$res) throw new Exception('passphrase is not valid for ',$this->keyfile); 
        $this->key_pass = $key_pass; 
        openssl_pkey_free($res);
    }
    throw new Exception('passphrase is empty');
  }

  function output($type = 'XML') {
    $type = strtoupper($type);

    if ($this->{'output'.$type}) return $this->{'output'.$type};

    throw new Exception(  $type.' is not found to output');
  }

  function decodeCDOC() {

    if (!$this->outputCDOC) throw new Exception('no CDOC to decodde');

    if (!preg_match('/^<\?xml version="1.0" encoding="UTF-8"/',$this->outputCDOC))  throw new Exception('invalid CDOC header');

    if (preg_match('#<HGWError>(.*)</HGWError>#s',$this->outputCDOC, $m)) {
        $this->errors = [ 'HGW error: '.htmlentities($m[1]) ];
        return false;
    }

    if (!preg_match('#<ds:X509Certificate>([^<]+)#s',$this->outputCDOC, $m)) throw new Exception('Cannot extract cert') ;
    $cert = $m[1];

    if (!preg_match('#</ds:X509Data></ds:KeyInfo><denc:CipherData><denc:CipherValue>([^<]+)#s',$this->outputCDOC, $m)) throw new Exception('Cannot extract transprot key');
    $transport_key_enc = $m[1];

    if (!preg_match('#</denc:EncryptedKey></ds:KeyInfo><denc:CipherData><denc:CipherValue>([^<]+)#s',$this->outputCDOC, $m)) throw new Exception('Cannot extract payload');
    $payload_enc = $m[1];

    if (!preg_match('#<denc:EncryptionProperty Name="Filename">([^<]+)#s',$this->outputCDOC, $m)) throw new Exception('Cannot find filename of xml file');
    $filename = $m[1];

    if (!preg_match('#<denc:EncryptionProperty Name="OriginalSize">([^<]+)#s',$this->outputCDOC, $m)) throw new Exception('Cannot extract filesize');
    $fsize = intval($m[1]);


    $private_key = openssl_pkey_get_private('file://'.$this->keyfile, $this->key_pass);
    if (!$private_key) throw new Exception('Cannot set private key from '.$this->keyfile);

    if (!openssl_private_decrypt(base64_decode($transport_key_enc),$transport_key,$private_key)) throw new Exception('Cannot decode transport key: '.$transport_key_enc );

    openssl_free_key($private_key);

    # decode to bdoc here
    $payload_enc_bin = base64_decode($payload_enc);
    $iv = substr($payload_enc_bin,0,16);
    $payload_enc_bin_body =  substr($payload_enc_bin,16);

    $payload_dec = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $transport_key, $payload_enc_bin_body, MCRYPT_MODE_CBC, $iv);

    if ($payload_dec === false) throw new Exception('Cannot decrypt payload');

    # FIXME: strip padding here
#    $payload_dec = rtrim($payload_dec , "\0\4");

    $this->outputBDOC = zlib_decode($payload_dec);

    # FIXME: check $fsize

    return $this->decodeBDOC($filename);

  }

  function decodeBDOC($filename) {
    # extract xml
    # FIXME: should signatures*.xml be parsed for files to extract ?
    $zipfile = $this->tmpdir.$this->CorrelationID.'.'.strtr($this->TrackingID,array('/' =>'_','\\' => '_')).'.BDOC.zip';
    if (!file_put_contents($zipfile,$this->outputBDOC)) throw new Exception('decodeBDOC: cannot save zip to '.$zipfile );
    $this->outputXML = file_get_contents('zip://'.$zipfile.'#'.$filename);
    unlink($zipfile);
    if (!$this->outputXML) return false;
    return true;
  }

  function encodeXML($xml) {
    if ($xml) $this->inputXML = $xml;
    $this->CorrelationID = rtrim(strtr(base64_encode(openssl_random_pseudo_bytes(15)), '+/', '-_'), '=');
    $this->RequestId = $this->TrackingID = null;
  	$this->outputCDOC = $this->outputBDOC = $this->outputXML = null;

    # do real encoding here
    $this->createBDOC();
    $this->createCDOC();
    return true;
  }

  function save($type = 'CDOC') {
    $type = strtoupper($type);
    $filename = $this->tmpdir.$this->CorrelationID.'.'.strtr($this->TrackingID,array('/' =>'_','\\' => '_')).'.'.$type;
    if ( !is_readable($filename) ) {
        return file_put_contents($filename,$this->{'output'.$type});
    } else {
      $this->errors = [ 'file already exists: '.$filename ];
      return false;
    }
  }

  function load($type = 'CDOC') {
    $type = strtoupper($type);
    if ( is_readable($this->tmpdir.$this->CorrelationID.'.'.$type) ) {
        $this->{'output'.$type} = file_get_contents($this->tmpdir.$this->CorrelationID.'.'.$type);
        return true;
    } else {
        return false;
    }
  }

  function getError() { return implode("\r\n",$this->errors); }

  function createBDOC() {

      if (!$this->inputXML) throw new Exception('createBDOC: inputXML is missing');

     $manifest = '<?xml version="1.0" encoding="utf-8"?>
      <manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"><manifest:file-entry manifest:media-type="application/vnd.etsi.asic-e+zip" manifest:full-path="/" /><manifest:file-entry manifest:media-type="text/xml" manifest:full-path="'.$this->CorrelationID.'.xml" /></manifest:manifest>';
     $mimetype = 'application/vnd.etsi.asic-e+zip';


    $cert = openssl_x509_read('file://'.$this->certfile);
    if (!$cert) throw new Exception('Cannot set cert from '.$this->certfile);

    preg_match('/(MII[^-]+)/',file_get_contents($this->certfile),$m);
    $cert_str = preg_replace('/\s/','',$m[1]);

    $signatures_tmpl = '<?xml version="1.0" encoding="UTF-8"?>
      <asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
      <ds:Signature Id="S0">
      <ds:SignedInfo Id="S0-SignedInfo"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>
      <ds:Reference Id="S0-ref-0" URI="'.$this->CorrelationID.'.xml"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>'.base64_encode(hash('sha256',$this->inputXML,1)).'</ds:DigestValue></ds:Reference>
      <ds:Reference Id="S0-ref-sp" Type="http://uri.etsi.org/01903#SignedProperties" URI="#S0-SignedProperties"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>##BASE64SIGNPROPHERE##</ds:DigestValue></ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue Id="S0-SIG">##BASE64SIGHERE##</ds:SignatureValue>
      <ds:KeyInfo Id="S0-KeyInfo"><ds:X509Data><ds:X509Certificate>'.$cert_str.'</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
      <ds:Object Id="S0-object-xades"><xades:QualifyingProperties Id="S0-QualifyingProperties" Target="#S0" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
        <xades:SignedProperties Id="S0-SignedProperties">
          <xades:SignedSignatureProperties Id="S0-SignedSignatureProperties">
            <xades:SigningTime>'.gmdate('Y-m-d\TH:i:s\Z').'</xades:SigningTime>
            <xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>'.base64_encode(openssl_x509_fingerprint($cert,'sha256',1)).'</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>'.implode(',',openssl_x509_parse($cert)['issuer']).'</ds:X509IssuerName><ds:X509SerialNumber>'.openssl_x509_parse($cert)['serialNumber'].'</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate>
            <xades:SignaturePolicyIdentifier><xades:SignaturePolicyId>
            <xades:SigPolicyId>
                <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.3.6.1.4.1.10015.1000.3.2.1</xades:Identifier>
            </xades:SigPolicyId>
            <xades:SigPolicyHash>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>
                <ds:DigestValue>3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs=</ds:DigestValue>
            </xades:SigPolicyHash>
            <xades:SigPolicyQualifiers><xades:SigPolicyQualifier>
                <xades:SPURI>https://www.sk.ee/repository/bdoc-spec21.pdf</xades:SPURI>
            </xades:SigPolicyQualifier></xades:SigPolicyQualifiers>
            </xades:SignaturePolicyId>
            </xades:SignaturePolicyIdentifier>
            <xades:SignerRole>
             <xades:ClaimedRoles><xades:ClaimedRole>ERP</xades:ClaimedRole></xades:ClaimedRoles>
            </xades:SignerRole>
          </xades:SignedSignatureProperties>
          <xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference="#S0-ref-0">
            <xades:MimeType>text/xml</xades:MimeType></xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
      </xades:SignedProperties>
      </xades:QualifyingProperties></ds:Object></ds:Signature>
      </asic:XAdESSignatures>';


    $xml = new DOMDocument( "1.0", "UTF-8" );
    $xml->validateOnParse = true;
    $xml->loadXML($signatures_tmpl);

    $sigprop_nodes = $xml->getElementsByTagName('SignedProperties');
    if (empty($sigprop_nodes[0])) throw new Exception('cannot find node "SignedProperties"' );
    $sigprop = $sigprop_nodes[0]->C14N();

    $digest_sigprop = trim(base64_encode(hash('sha256',$sigprop,1)));

    $signatures = strtr($signatures_tmpl,array('##BASE64SIGNPROPHERE##' => $digest_sigprop));
    $xml->loadXML($signatures);

    $sign_nodes = $xml->getElementsByTagName('SignedInfo');
    if (empty($sign_nodes[0])) throw new Exception('cannot find node "SignedInfo"' );
    $sign = $sign_nodes[0]->C14N();

    $private_key = openssl_pkey_get_private('file://'.$this->keyfile,$this->key_pass);
    if (!$private_key) throw new Exception('createBDOC: Cannot set private key from '.$this->keyfile);

    if (!openssl_sign($sign, $signature, $private_key, 'RSA-SHA256')) throw new Exception('Failure Signing Data: ' . openssl_error_string() );
    openssl_free_key($private_key);

    $signatures = strtr($signatures,array('##BASE64SIGHERE##' => base64_encode($signature)));

    $filename = 'output/'.$this->CorrelationID.'.zip';

    $zip = new \ZipArchive();
    $zip->open($filename, ZipArchive::CREATE);
    $zip->addFromString('mimetype', $mimetype);
    $zip->setCompressionName('mimetype', ZipArchive::CM_STORE);
    $zip->addFromString($this->CorrelationID.'.xml', $this->inputXML);
    $zip->addFromString('META-INF/manifest.xml', $manifest);
    $zip->addFromString('META-INF/signatures1.xml', $signatures);
    $zip->close();

    $this->inputBDOC = file_get_contents($filename);

    unlink($filename);

  }

  function createCDOC() {
    if (!$this->sgw_certfile) throw new Exception('createCDOC: SGW cert is missing');
    if (!$this->inputBDOC) throw new Exception('createCDOC: inputBDOC is missing');

    $transport_key = strtr(openssl_random_pseudo_bytes(16),array("\0"=>'A'));
    $iv = strtr(openssl_random_pseudo_bytes(16),array("\0"=>'B'));

    $sgw_cert = openssl_x509_read('file://'.$this->sgw_certfile);
    if (! $sgw_cert) throw new Exception('Cannot set cert from '.$this->sgw_certfile);

    preg_match('/(MII[^-]+)/',file_get_contents($this->sgw_certfile),$m);
    $sgw_cert_str = trim($m[1]);

    if (! openssl_public_encrypt($transport_key,$transport_key_enc,$sgw_cert) )  throw new Exception('Cannot encode with '.$this->sgw_certfile);

    $transport_key_enc = trim(chunk_split(base64_encode($transport_key_enc),64,"\n"));

    $payload = zlib_encode($this->inputBDOC,ZLIB_ENCODING_DEFLATE);

    # there are two paddings always there X.923 (00 00 00 04) and then ANSI PKCS7 (04 04 04 04)
    # looks like 
    # 00001e60  9e fe 0b 57 09 c9 ac 00  00 00 00 00 00 00 00 09  |...W............|
    # 00001e70  10 10 10 10 10 10 10 10  10 10 10 10 10 10 10 10  |................|

    # X.923
    $padding = 16 - (strlen($payload) % 16);
    if (!$padding) $padding = 16;
    # FIXME: sure ?
    if ($padding == 1) $padding = 17; 
    $payload .= str_repeat("\0",$padding-1).chr($padding);

    # PKCS7 
    $payload .= str_repeat(chr('16'),16);

    file_put_contents('output/raw',$payload);

    $payload = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $transport_key, $payload, MCRYPT_MODE_CBC, $iv);

    if ($payload === false) throw new Exception('cannot encrypt');

    $payload = $iv.$payload;

    $payload = chunk_split(base64_encode($payload),64,"\n");

    $this->inputCDOC = '<?xml version="1.0" encoding="UTF-8" ?><denc:EncryptedData xmlns:denc="http://www.w3.org/2001/04/xmlenc#" MimeType="http://www.isi.edu/in-noes/iana/assignments/media-types/application/zip"><denc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></denc:EncryptionMethod><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">';
    $this->inputCDOC .= '<denc:EncryptedKey Id="'.openssl_x509_parse($sgw_cert)['subject']['CN'].'" Recipient="'.openssl_x509_parse($sgw_cert)['subject']['CN'].'">';
    # FIXME: HGW ?
#    $this->inputCDOC .= '<denc:EncryptedKey Id="'.openssl_x509_parse($sgw_cert)['subject']['CN'].'" Recipient="SGW">';
    $this->inputCDOC .= '<denc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"></denc:EncryptionMethod><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>'.$sgw_cert_str.'</ds:X509Certificate></ds:X509Data></ds:KeyInfo><denc:CipherData><denc:CipherValue>'.$transport_key_enc.'</denc:CipherValue></denc:CipherData></denc:EncryptedKey></ds:KeyInfo><denc:CipherData><denc:CipherValue>'.$payload.'</denc:CipherValue></denc:CipherData>';
    $this->inputCDOC .= '<denc:EncryptionProperties><denc:EncryptionProperty Name="LibraryVersion">'.self::LIBNAME.'|'.self::LIBVER.'</denc:EncryptionProperty><denc:EncryptionProperty Name="DocumentFormat">ENCDOC-XML|1.0</denc:EncryptionProperty><denc:EncryptionProperty Name="Filename">'.$this->CorrelationID.'.xml</denc:EncryptionProperty><denc:EncryptionProperty Name="OriginalMimeType">text/xml</denc:EncryptionProperty><denc:EncryptionProperty Name="OriginalSize">'.strlen($this->inputBDOC).'</denc:EncryptionProperty></denc:EncryptionProperties></denc:EncryptedData>'; 
  }

}
