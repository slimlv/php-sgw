<?php


require_once('sgw.class.php');
require_once('sgwtask.class.php');

$key_file = 'my.key';
$cert_file = 'my.crt';

is_readable($key_file) or die('cannot read file "'.$key_file.'"');
is_readable($cert_file) or die('cannot read file "'.$cert_file.'"');


$processor = new SGW($key_file,$cert_file);
$processor->transport_cert = 'sgwCA.cer';


 print "<h1>SEND:</h1>";
 print '<form method="POST" action="?">
 <textarea name="data" rows="20" cols="50"><?xml version="1.0" encoding="UTF-8"?>
 <GetBalance>
  <IBAN>LVN23459892345</IBAN>
   <Date>2016-04-04</Date>
   </GetBalance></textarea>
   <input type="submit" name="send"></form>';


if (isset($_POST['data'])) {
    $send_task = new SGWTask($key_file,$cert_file,'swedbank.cer');
    $send_task->tmpdir = 'output/';
    $send_task->encodeXML(trim($_POST['data'])) || die('cannot load XML:'.$task->getError());
    $status = $processor->send($send_task);
    if ($status === false) die('cannot send task due error:'.$processor->getError());
    print "<h2>sent: ".$send_task->CorrelationID."</h2>";
    #print '<pre>'.htmlentities(print_r($processor->debug,1));
}

 print "<h1>RECEIVE:</h1>";
 print "<a href='?'>receive</a>";
 $receive_task = new SGWTask($key_file,$cert_file);
 $receive_task->tmpdir = 'output/';

 $processor->debug = array();

  while ( true ) {
    sleep(1);
    $status = $processor->receive($receive_task);
    if ( $status ) { 
        print "<h2>received: ".$receive_task->CorrelationID."</h2>";
	    if ( !$receive_task->decodeCDOC() ) {
            print $receive_task->getError();
            $processor->purge($receive_task);
        } else {
 #           print "saving...";
 #           $receive_task->save('CDOC') or print('error saving CDOC:'.$receive_task->getError());
 #           $receive_task->save('BDOC') or print('error saving BDOC:'.$receive_task->getError());
 #           $receive_task->save('XML') or print('error saving XML:'.$receive_task->getError());
            $processor->purge($receive_task);
            print 'Output: <br><ore>'.htmlentities($receive_task->output()).'</pre>';
        }
    }

   if ( $status === null ) {
   	print "<br>no more received";
	break;
   }
}



