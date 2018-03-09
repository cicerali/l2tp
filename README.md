l2tp message encode/decoder
*Hidden AVP not supported yet
*Basic encode/decode tests for all messages
*Required glibc 2.9+


Test scenario:

|-------|
|CREATE |
|A TEST |
|MESSAGE|
|-------|
  ||
  ||		 Send	
ENCODE     ------>  |----------|
			  	    |	   	   |
				    | LOOPBACK |
		   Receive  |		   |
DECODE	  <-------  |----------|
  ||	
  ||	    Send	
ENCODE    ------->  |----------|
				    |	   	   |
				    | LOOPBACK |
		  Receive   |		   |
COMPARE	  <-------  |----------|
