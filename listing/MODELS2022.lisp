(in-package :shop-user)
; This extremely simple example shows some of the most essential
;   features of SHOP2.

(defdomain sec (
	
	
	; For simplicity, not performing an operation has a negative cost. 
	; In future versions positive costs must be considered in all other actions.
	(:operator (!na) () () () -20)
	
	; The outcome of a_d
	(:operator (!done) () () ())


	;     #                                  
	;    # #   #    # #  ####  #    #  ####  
	;   #   #   #  #  # #    # ##  ## #      
	;  #     #   ##   # #    # # ## #  ####  
	;  #######   ##   # #    # #    #      # 
	;  #     #  #  #  # #    # #    # #    # 
	;  #     # #    # #  ####  #    #  ####  

	(:- (has ?agent ?info) (has ?agent ?info ?someLocation ?someformat))
   
	(:- (has ?agent ?info ?someformat) (has ?agent ?info ?someLocation ?someformat))
   
	; Information is readable in all cases it is in plaintext 
	; except when it is in a USB or otther such medium.
	; In that case it has to be transfered to a device.
	(:- (can-read ?agent ?info) 
		(and 
			(or (has ?agent ?info)
				(has ?agent (signed ?info (key ?whoever private)))
			)
			(not ((has ?agent ?info usb ?someformat)))
		)
	)


	; Axiom to handle reflexivity of shared key predicate between two parties
	(:- (has ?user (key ?user ?otheruser shared) local-drive digital-file)
		((has ?user (key ?otheruser ?user shared) local-drive digital-file))
	)


	;#####                                                                           
	;#     #  ####  #    # #    # #    # #    # #  ####    ##   ##### #  ####  #    # 
	;#       #    # ##  ## ##  ## #    # ##   # # #    #  #  #    #   # #    # ##   # 
	;#       #    # # ## # # ## # #    # # #  # # #      #    #   #   # #    # # #  # 
	;#       #    # #    # #    # #    # #  # # # #      ######   #   # #    # #  # # 
	;#     # #    # #    # #    # #    # #   ## # #    # #    #   #   # #    # #   ## 
	; #####   ####  #    # #    #  ####  #    # #  ####  #    #   #   #  ####  #    # 
  
	; #######                             #                                          
	; #       #    #  ####  #####         #       ###### #    # ###### #       ####  
	; #       ##   # #    # #    #        #       #      #    # #      #      #      
	; #####   # #  # #      #    #        #       #####  #    # #####  #       ####  
	; #       #  # # #      #####  ###    #       #      #    # #      #           # 
	; #       #   ## #    # #   #  ###    #       #       #  #  #      #      #    # 
	; ####### #    #  ####  #    # ###    ####### ######   ##   ###### ######  ####  

	;Can send info in plaintext and unsigned
	(:method 
       (send-info ?sender ?recipient ?info) ;name
       ( (has ?sender ?info) )
       ((send-information ?sender ?recipient ?info))
    )
	
	;Can send info that is encrypted with symmetric encryption
	(:method 
       (send-info ?sender ?recipient ?info) ;name
       ( (has ?sender (encrypted ?info (key ?p1 ?p2 ?p3))))
       ( (send-information ?sender ?recipient (encrypted ?info (key ?p1 ?p2 ?p3))) )
    )	

	;Can send info that is encrypted with asymmetric encryption
	(:method 
       (send-info ?sender ?recipient ?info) ;name
       ( (has ?sender (encrypted ?info (key ?p1 ?p2))))
       ( (send-information ?sender ?recipient (encrypted ?info (key ?p1 ?p2))) )
    )	

	;Can send info that is signed
	(:method
       (send-info ?sender ?recipient ?info) ;name
       ( (has ?sender (signed ?info (key ?signer private))) 
	   )
       ( (send-information ?sender ?recipient (signed ?info (key ?signer private))) )
    )	

	;Can send info that is both signed and encrypted symmetrically.
	(:method 
       (send-info ?sender ?recipient ?info)
       ( (has ?sender (encrypted (signed ?info (key ?signer private)) (key ?p1 ?p2 ?p3))) )
       ( (send-information ?sender ?recipient (encrypted (signed ?info (key ?signer private)) (key ?p1 ?p2 ?p3))) )
    )	

	;Can send info that is both signed and encrypted asymmetrically.
	(:method 
       (send-info ?sender ?recipient ?info)
       ( (has ?sender (encrypted (signed ?info (key ?signer private)) (key ?p1 ?p2))) )
       ( (send-information ?sender ?recipient (encrypted (signed ?info (key ?signer private)) (key ?p1 ?p2))) )
    )	


	;#     #                             
	;##   ##  ####  #####  ######  ####  
	;# # # # #    # #    # #      #      
	;#  #  # #    # #    # #####   ####  
	;#     # #    # #    # #           # 
	;#     # #    # #    # #      #    # 
	;#     #  ####  #####  ######  ####  

	;You can email information if it is email-transmissible
    (:method 
       (send-information ?sender ?recipient ?info) ;name
       (	(is-email-transmissible ?sender ?recipient ?info)
			(allow email) ; "allows" predicates added to reduce search space
	   )
       ((!email ?sender ?recipient ?info))
    )

	;You can text information if it is text-transmissible
    (:method 
       (send-information ?sender ?recipient ?info) ;name
	   (	(is-sms-transmissible ?sender ?recipient ?info)
			(allow sms)
	   )
       ((!sms ?sender ?recipient ?info) )
    )

    ;You can send information by phone/voice if it is phone-transmissible 
	;(e.g. a short password or number)
	(:method 
       (send-information ?sender ?recipient ?info) ;name
	   (	(is-phonecall-transmissible ?sender ?recipient ?info)
			(allow phonecall)
	   )
       ((!by-phonecall-exchange ?sender ?recipient ?info))
    )

	;You can meet the person and pass a letter or a usb stick or CD
    (:method 
       (send-information ?sender ?recipient ?info) ;name
	   (	(is-in-person-transmissible ?sender ?recipient ?info)
			(allow in-person)
	   )
       ((in-person-exchange ?sender ?recipient ?info)) ; this is a method
    )

    ;You can meet the person and tell them the information orally
	(:method 
       (send-information ?sender ?recipient ?info) ;name
	   (	(is-in-person-orally-transmissible ?sender ?recipient ?info)
			(allow in-person)
	   )
       ((!in-person-oral-exchange ?sender ?recipient ?info))
    )


  
 
	;  #####                             #                                  
	; #     #  ####  #    # #    #      # #   #    # #  ####  #    #  ####  
	; #       #    # ##  ## ##  ##     #   #   #  #  # #    # ##  ## #      
	; #       #    # # ## # # ## #    #     #   ##   # #    # # ## #  ####  
	; #       #    # #    # #    #    #######   ##   # #    # #    #      # 
	; #     # #    # #    # #    #    #     #  #  #  # #    # #    # #    # 
	;  #####   ####  #    # #    #    #     # #    # #  ####  #    #  ####  
 
	;because the agent is assumed to save the document to the local drive
	(:- (has ?agent ?info local-drive ?format) ((has ?agent ?info mailbox ?format))) 
	
	;because the agent is assumed to synch the shared folder with the local one
	(:- (has ?agent ?info local-drive ?format) ((has ?agent ?info shared-folder ?format))) 

	; printed and hardwritten are special cases of the paper format
	(:- (has ?someone ?info ?somewhere paper) ((has ?someone ?info ?somewhere printed))) 
	(:- (has ?someone ?info ?somewhere paper) ((has ?someone ?info ?somewhere handwritten))) 


	; #######                        
	; #       #    #   ##   # #      
	; #       ##  ##  #  #  # #      
	; #####   # ## # #    # # #      
	; #       #    # ###### # #      
	; #       #    # #    # # #      
	; ####### #    # #    # # ###### 
 
	; Something can be sent by email if it is available in a digital file, in one of the 
	; sender's devices.
    (:- (is-email-transmissible ?sender ?recipient ?info) 
		(and 	
			(has ?sender ?recipient email-address)
			(or	(has ?sender ?info local-drive digital-file)
				(has ?sender ?info mailbox digital-file)
				(has ?sender ?info shared-folder digital-file)
				(has ?sender ?info phone digital-file)
				(has ?sender ?info usb digital-file)
			)
		)
	)
	
	
	; Email Information
	; Preconditions:
	;		(o) Email Transmissible
	; Effects:
	;		(o) The message appears as a digital file in both sender's 
	;			and recipients mailboxes 
	;		(o) The information has passed through data network
    (:operator 
	    (!email ?sender ?recipient ?info) 
		(	(is-email-transmissible ?sender ?recipient ?info)
		)
		() 
		(	(has ?recipient ?info mailbox digital-file) 
			(has ?sender ?info mailbox digital-file) 
			(pass-through-data-network ?info)
		)
	)


	;  #####  #     #  #####  
	; #     # ##   ## #     # 
	; #       # # # # #       
	;  #####  #  #  #  #####  
	;       # #     #       # 
	; #     # #     # #     # 
	;  #####  #     #  #####  

	; Something can be sent by sms if it is available in a digital file, in one of the 
	; sender's devices.
	(:- (is-sms-transmissible ?sender ?recipient ?info) 
		(and 	
			(has ?sender ?recipient phone-number)
			(or	(has ?sender ?info local-drive digital-file) ;transfer
				(has ?sender ?info mailbox digital-file) ;save and transfer
				(has ?sender ?info shared-folder digital-file) ;download and transfer
				(has ?sender ?info phone digital-file) 
				(has ?sender ?info usb digital-file) ;connect digital
			)
		)
	)

	; Text (sms) Information
	; Preconditions:
	;		(o) Sms Transmissible
	; Effects:
	;		(a) The message appears as a digital file in both sender's 
	;			and recipients phones
	;		(a) The information has passed through mobile network
    (:operator 
	    (!sms ?sender ?recipient ?info) 
		(	(is-sms-transmissible ?sender ?recipient ?info)
		)
		() 
		(	(has ?recipient ?info phone digital-file) 
			(has ?sender ?info phone digital-file) 
			(pass-through-mobile-network ?info)
		)
	)


	; ######                                  #####                       
	; #     # #    #  ####  #    # ######    #     #   ##   #      #      
	; #     # #    # #    # ##   # #         #        #  #  #      #      
	; ######  ###### #    # # #  # #####     #       #    # #      #      
	; #       #    # #    # #  # # #         #       ###### #      #      
	; #       #    # #    # #   ## #         #     # #    # #      #      
	; #       #    #  ####  #    # ######     #####  #    # ###### ###### 


	; Something is transmissible through a phonecall if it is dictatable
	; (e.g. of a reasonable size) and is available in any readable form.
    (:- (is-phonecall-transmissible ?sender ?recipient ?info) 
		(and 	
			(has ?sender ?recipient phone-number)
			(is ?info dictatable)
			(or	(has ?sender ?info local-drive digital-file) ;open and read
				(has ?sender ?info mailbox digital-file) ;open and read
				(has ?sender ?info shared-folder digital-file) ;open and read
				(has ?sender ?info phone digital-file) ;read
				(has ?sender ?info usb digital-file) ;open and read
				(has ?sender ?info physical paper) ;read
			)
		)
	)

	; Phonecall Transmission of Information
	; Preconditions:
	;		(o) Phonecall transmissible
	; Effects:
	;		(o) The receipient is assumed to have handwritten the spoken information on paper
	;		(o) The information was exchanged by voice through phone.
   (:operator 
		(!by-phonecall-exchange ?sender ?recipient ?info) 
		(	(is-phonecall-transmissible ?sender ?recipient ?info)
		)
		()
		( 	(has ?recipient ?info physical handwritten)
			(shared-by-phone ?sender ?recipient ?info)
		)
	)


	; ###           ######                                     
	;  #  #    #    #     # ###### #####   ####   ####  #    # 
	;  #  ##   #    #     # #      #    # #      #    # ##   # 
	;  #  # #  #    ######  #####  #    #  ####  #    # # #  # 
	;  #  #  # #    #       #      #####       # #    # #  # # 
	;  #  #   ##    #       #      #   #  #    # #    # #   ## 
	; ### #    #    #       ###### #    #  ####   ####  #    # 

	; Something is transmissible through an in person material exchange
	; Material can be paper or other digital medium (USB, CD, etc.)
    (:- (is-in-person-transmissible ?sender ?recipient ?info) 
		(and 	
			(or	(can-meet ?sender ?recipient)  
				(can-meet ?recipient ?sender)
			)
			(or	(has ?sender ?info local-drive digital-file) ;put in USB or print it
				(has ?sender ?info mailbox digital-file) ;put in USB or print it
				(has ?sender ?info shared-folder digital-file) ;download put in USB or print it
				(has ?sender ?info phone digital-file) ;put in USB or print it or print it
				(has ?sender ?info usb digital-file) ; great
				(has ?sender ?info physical paper) ;just carry the document
			)
		)
	)


	; How to exchange digital information in person
	; Preconditions:
	;	(o) in-person transmissible
	;	(o) the sender has the document in a digital-file format
	(:method 
		(in-person-exchange ?sender ?recipient ?info) ;name
		(	(has ?sender ?info digital-file)
			(is-in-person-transmissible ?sender ?recipient ?info)
		) 
		(	(!in-person-exchange-digital ?sender ?recipient ?info)
		)
	)

	; How to exchange paper information in person
	; Preconditions:
	;	(o) in-person transmissible (printing is assumed to be trivially possible and implied)
	(:method 
		(in-person-exchange-digital ?sender ?recipient ?info) ;name
		(	(is-in-person-transmissible ?sender ?recipient ?info)
				(has ?sender ?info physical)
		) 
		(	(!in-person-exchange-paper ?sender ?recipient ?info)
		)
	)


	; In person exchange - digital
	; Preconditions:
	;		(o) In-person transmissible
	; Effects:
	;		(o) The information is in digital format in an external or internal location
	;		(o) The information was exchanged through in person exchange
   (:operator 
		(!in-person-exchange-digital ?sender ?recipient ?info) 
		(	
			(is-in-person-transmissible ?sender ?recipient ?info)
		)
		()
		( 	
			(has ?recipient ?info physical digital-file); refers to the presence of a usb on the person's desk
			(has ?recipient ?info local-drive digital-file);we assume the person will just copy the file into their disk.
			(shared-in-person ?sender ?recipient ?info)
		)
	)


	; In person exchange - paper-based
	; Preconditions:
	;		(o) In-person transmissible
	; Effects:
	;		(o) The information is in physical format
	;		(o) The information was exchanged through in person exchange
   (:operator 
		(!in-person-exchange-paper ?sender ?recipient ?info) 
		(	
			(is-in-person-transmissible ?sender ?recipient ?info)
			(has ?sender ?info physical ?format)
		)
		()
		( 	(has ?recipient ?info physical ?format)
			(shared-in-person ?sender ?recipient ?info)
		)
	)



	; ###           ######                                        #######                      
	;  #  #    #    #     # ###### #####   ####   ####  #    #    #     # #####    ##   #      
	;  #  ##   #    #     # #      #    # #      #    # ##   #    #     # #    #  #  #  #      
	;  #  # #  #    ######  #####  #    #  ####  #    # # #  #    #     # #    # #    # #      
	;  #  #  # #    #       #      #####       # #    # #  # #    #     # #####  ###### #      
	;  #  #   ##    #       #      #   #  #    # #    # #   ##    #     # #   #  #    # #      
	; ### #    #    #       ###### #    #  ####   ####  #    #    ####### #    # #    # ###### 

	; The information exists in some format, it is dictatable and the persons can meet
    (:- (is-in-person-orally-transmissible ?sender ?recipient ?info) 
		(and 	
			(or	(can-meet ?sender ?recipient)
				(can-meet ?recipient ?sender)
			)
			(is ?info dictatable)
			(or	(has ?sender ?info local-drive digital-file) ;print and read
				(has ?sender ?info mailbox digital-file) ;print and read
				(has ?sender ?info shared-folder digital-file) ;open and read
				(has ?sender ?info phone digital-file) ;read
				(has ?sender ?info usb digital-file) ;open and read
				(has ?sender ?info physical paper) ;read
			)
		)
	)



	; In person exchange - poral
	; Preconditions:
	;		(o) In-person orally transmissible
	; Effects:
	;		(o) The information is assumed to be recorded on paper
	;		(o) The information was exchanged orally through in person exchange
	(:operator 
		(!in-person-oral-exchange ?sender ?recipient ?info)
		(	(is-in-person-orally-transmissible ?sender ?recipient ?info)
		)
		()
		( 	(has ?recipient ?info physical handwritten)
			(shared-orally-in-person ?sender ?recipient ?info)
		)
	)


	; #######                                                         
	;    #    #####    ##   #    #  ####  ######  ####  #####  #    # 
	;    #    #    #  #  #  ##   # #      #      #    # #    # ##  ## 
	;    #    #    # #    # # #  #  ####  #####  #    # #    # # ## # 
	;    #    #####  ###### #  # #      # #      #    # #####  #    # 
	;    #    #   #  #    # #   ## #    # #      #    # #   #  #    # 
	;    #    #    # #    # #    #  ####  #       ####  #    # #    # 


	;A transformation may not be needed
	(:method 
		(transform ?agent ?info) ;name
		() 
		((!na))
	)

	;A transformation may be needed
   (:method 
		(transform ?agent ?info) ;name
		;Case 1: if it is printed it can be scanned
		((has ?agent ?info ?somemedium printed)) 
		((!scan ?agent ?info))
		;Case 2: if it is handwritten it can be typed-up
		((has ?agent ?info ?somemedium handwritten)) 
		((!type-up ?agent ?info))
		;Case 3: if it is in a usb it can be copied to a PC.
		((has ?agent ?info usb ?someformat)) 
		((!copy-to-pc ?agent ?info))
		;Case 4: if it is in the PC it can be copied to a USB.
		((has ?agent ?info local-drive ?someformat)) 
		((!copy-to-a-usb ?agent ?info))
    )


	; Scan
	; Preconditions:
	;		(o) the information is available in a printed format
	; Effects:
	;		(o) The information exists digitally in the local drive
	(:operator 
		(!scan ?agent ?info) 
		(	(has ?agent ?info ?somemedium printed)
		)
		()
		( 	(has ?agent ?info local-drive digital-file)
		)
	)


	; Type-up
	; Preconditions:
	;		(o) the information is available in a paper format (hand-written or otherwise)
	; Effects:
	;		(o) The information exists digitally in the local drive
   (:operator 
		(!type-up ?agent ?info) 
		(	(has ?agent ?info ?somemedium paper)
		)
		()
		( 	(has ?agent ?info local-drive digital-file)
		)
	)

	; Copy to PC
	; Preconditions:
	;		(o) the information is available inside a USB stick 
	;		(or CD or other portable digital medium)
	; Effects:
	;		(o) The information exists digitally in the local drive
   (:operator 
		(!copy-to-pc ?agent ?info) 
		(	(has ?agent ?info usb ?format)
		)
		()
		( 	(has ?agent ?info local-drive ?format)
		)
	)


	; Copy to USB
	; Preconditions:
	;		(o) the information is available in the PC or phone
	; Effects:
	;		(o) The information exists digitally in a USB
   (:operator 
		(!copy-to-a-usb ?agent ?info) 
		(	(or	(has ?agent ?info local-drive ?format)
			(has ?agent ?info phone ?format))
		)
		()
		( 	(has ?agent ?info usb ?format)
		)
	)










	; #######  #     #   #####   ######   #     #  ######   #######  ###  #######  #     # 
	; #        ##    #  #     #  #     #   #   #   #     #     #      #   #     #  ##    # 
	; #        # #   #  #        #     #    # #    #     #     #      #   #     #  # #   # 
	; #####    #  #  #  #        ######      #     ######      #      #   #     #  #  #  # 
	; #        #   # #  #        #   #       #     #           #      #   #     #  #   # # 
	; #        #    ##  #     #  #    #      #     #           #      #   #     #  #    ## 
	; #######  #     #   #####   #     #     #     #           #     ###  #######  #     # 

  
  

	;  #####                                                   
	; #     # #   # #    # #    # ###### ##### #####  #  ####  
	; #        # #  ##  ## ##  ## #        #   #    # # #    # 
	;  #####    #   # ## # # ## # #####    #   #    # # #      
	;       #   #   #    # #    # #        #   #####  # #      
	; #     #   #   #    # #    # #        #   #   #  # #    # 
	;  #####    #   #    # #    # ######   #   #    # #  ####  

	; How to encrypt unsigned information 
	;	Preconditions:
	;		(a) the sender has the information in a digital format
	;		(b) the sender has a shared key in a digital format
	;		Note: it is assumed that symmetric encryption can be handled by 
	;		document viewers and word processors.
	(:method 
		(encrypt-information ?sender ?recipient ?info) ;name
		(	(has ?sender ?info digital-file)
			(or	(has ?sender (key ?sender ?recipient shared) digital-file)
				(has ?sender (key ?recipient ?sender shared) digital-file)
			)
		) 
		(	(!symmetric-encrypt ?sender ?recipient ?info 
			(key ?sender ?recipient shared))
		)
	)

	; Encrypt unsigned information 
	; Preconditions:
	;		[(o) Placed in method]
	; Effects:
	;		(a) the user has the info now encrypted info with the shared key 
	;		(a) the information now fits email and web exchange
	(:operator 
		(!symmetric-encrypt ?sender ?recipient ?info ?key) 
		() 
		() 
		(	(has ?sender (encrypted ?info (key ?sender ?recipient shared)) local-drive digital-file)
		)
		200 ;a cost to discourage choice of encryption unless needed 
	)
  
	; How to symmetrically decrypt unsigned information 
	;	Preconditions:
	;		(a) the recipient has the encrypted information in digital format
	;		(b) the recipient has the shared key with the sender in digital format
	(:method 
		(decrypt-information ?sender ?recipient ?info) ;name
		(
			(has ?recipient 
				(encrypted ?info (key ?sender ?recipient shared)) digital-file)
			(has ?recipient (key ?sender ?recipient shared) digital-file)
		)
		((!symmetric-decrypt ?recipient ?sender ?info))
	)

	; Symmetrically decrypt unsigned information 
	;	Preconditions:
	;		(o) Addressed in the method
	; Effects:
	;		(a) the recipient now has the info
	;		(b) the info is now at the recipients local drive
  	(:operator 
		(!symmetric-decrypt ?recipient ?sender ?info) 
		() 
		() 
		((has ?recipient ?info local-drive digital-file))
	)
  


	;  #####                                
	; #     # #  ####  #    # ###### #####  
	; #       # #    # ##   # #      #    # 
	;  #####  # #      # #  # #####  #    # 
	;       # # #  ### #  # # #      #    # 
	; #     # # #    # #   ## #      #    # 
	;  #####  #  ####  #    # ###### #####  

	; How to encrypt signed information 
	;	Preconditions:
	;		(a) the sender has the signed information (with some signature) in a digital format
	;		(b) the sender has a shared key in a digital format
	(:method 
		(encrypt-information ?sender ?recipient ?info) ;name
		(	(has ?sender (signed ?info (key ?agent private)) digital-file)
			(has ?sender (key ?sender ?recipient shared) digital-file) 
		) 
		((!symmetric-encrypt-signed ?sender (signed ?info (key ?agent private)) (key ?sender ?recipient shared)))
	)

	; Encrypt signed information 
	;	Preconditions:
	;		[(o) Placed in method]
	; Effects:
	;		(a) the user has the info now encrypted info with the shared key in their local drive
	(:operator 
		(!symmetric-encrypt-signed ?user ?info ?key) 
		() 
		() 
		( (has ?user (encrypted ?info ?key) local-drive digital-file)
		)
	)
  
	; How to symmetrically decrypt signed information 
	;	Preconditions:
	;		(a) the recipient has the encrypted and signed information
	;		(b) the recipient has the shared key with the sender
	(:method 
		(decrypt-information ?sender ?recipient ?info) ;name
		(	(has ?recipient (encrypted (signed ?info (key ?agent private)) 
					(key ?encryptor ?recipient shared)) digital-file)
			(has ?recipient (key ?encryptor ?recipient shared) digital-file)
		)
		((!symmetric-decrypt-signed ?recipient ?sender ?info))
	)

	; Symmetrically decrypt signed information 
	;	Preconditions:
	;		[(o) Placed in method]
	; Effects:
	;		(a) the recipient now has the signed info in their local drive
	;		(b) the info is now at the recipients local drive
	(:operator 
	(!symmetric-decrypt-signed ?recipient ?sender ?info) 
		(	(has ?recipient (encrypted (signed ?info (key ?agent private)) 
					(key ?encryptor ?recipient shared)) digital-file)
			(has ?recipient (key ?encryptor ?recipient shared) digital-file)
		)
		() 
		(	(has ?recipient (signed ?info (key ?agent private)) 
				local-drive digital-file) 
		)
	)


	;    #                                                            
	;   # #    ####  #   # #    # #    # ###### ##### #####  #  ####  
	;  #   #  #       # #  ##  ## ##  ## #        #   #    # # #    # 
	; #     #  ####    #   # ## # # ## # #####    #   #    # # #      
	; #######      #   #   #    # #    # #        #   #####  # #      
	; #     # #    #   #   #    # #    # #        #   #   #  # #    # 
	; #     #  ####    #   #    # #    # ######   #   #    # #  ####  

	; #######                                         
	; #       #    #  ####  #####  #   # #####  ##### 
	; #       ##   # #    # #    #  # #  #    #   #   
	; #####   # #  # #      #    #   #   #    #   #   
	; #       #  # # #      #####    #   #####    #   
	; #       #   ## #    # #   #    #   #        #   
	; ####### #    #  ####  #    #   #   #        #   


	; How to asymmetrically encrypt unsigned information 
	;	Preconditions:
	;		(a) the sender has the information in digital format
	;		(b) the sender has the public key of the recipient
	;		(c) the sender has encryption software
	(:method 
		(encrypt-information ?sender ?recipient ?info) ;name
		(
			(has ?sender ?info digital-file)
			(has ?sender (key ?recipient public)) 
			(has ?sender encryption-software)
		)
		(	(!asymmetric-encrypt ?sender ?recipient ?info (key ?recipient public)))
	)


	; How to asymmetrically encrypt signed information 
	;	Preconditions:
	;		(a) the sender has the public key of the recipient
	;		(b) the sender has the information signed by anyone's private key
	;		(c) the sender has encryption software
    (:method 
		(encrypt-information ?sender ?recipient ?info) ;name
		(	(has ?sender (key ?recipient public) digital-file) 
			(has ?sender (signed ?info (key ?agent private)) digital-file)
			(has ?sender encryption-software)
		)
		(	(!asymmetric-encrypt
				?sender 
				?recipient 
				(signed ?info (key ?agent private)) 
				(key ?recipient public)
			)
		)
    )


	; How to encrypt-information 
	;	Preconditions:
	;		[(o) Handled by the method]
	; Effects:
	;		(a) the user has the info now encrypted info with the recipients public key 
	;			and as a digital file
	(:operator 
		(!asymmetric-encrypt ?sender ?recipient ?info ?key) 
		() 
		()
		(	(has ?sender (encrypted ?info ?key) local-drive digital-file)
		)
		500
	)


	; Asymmetricaly enrcypt signed information
	;	Preconditions:
	;		[(o) Handled in the method
	;	Effects:
	;		(a) the encrypted signed information
;	(:operator 
;		(!asymmetric-encrypt-signed ?sender ?recipient ?info ?key) 
;		() 
;		() 
;		(	(has ?sender (encrypted ?info ?key) local-drive digital-file)
;		)
;		5
;	  )

	;No Encryption needed - if possible
    (:method 
		(encrypt-information ?sender ?recipient ?info) ;name
		()
		((!na)) ; don't do anything
	)
  


	; ######                                          
	; #     # ######  ####  #####  #   # #####  ##### 
	; #     # #      #    # #    #  # #  #    #   #   
	; #     # #####  #      #    #   #   #    #   #   
	; #     # #      #      #####    #   #####    #   
	; #     # #      #    # #   #    #   #        #   
	; ######  ######  ####  #    #   #   #        #   
	
	; How to assymetrically decrypt information - information already available in plaintext
	;	Preconditions:
	;		(o) the recipient has the information already
	(:method 
		(decrypt-information ?sender ?recipient ?info) ;name
		((has ?recipient ?info))
		((!na)) ; don't do anything
	)

	; How to assymetrically decrypt information - information available in signed format
	;	Preconditions:
	;		(o) the recipient has the information already
    (:method 
      (decrypt-information ?sender ?recipient ?info) ;name
      ((has ?recipient (signed ?info (key ?agent private))))
      ((!na)) ; don't do anything
    )

    ; How to assymetrically decrypt information - information available only encrypted
	;	Preconditions:
	;		(a) the recipient has the encrypted information with own public key
	;		(b) the recipient has the private key
	;		(c) the sender has encryption software
    (:method 
		(decrypt-information ?sender ?recipient ?info) ;name
		(
			(has ?recipient (encrypted ?info (key ?recipient public)))  
			(has ?recipient (key ?recipient private))
			(has ?recipient encryption-software)
		)
		(	(!asymmetric-decrypt ?sender ?recipient 
				(encrypted ?info (key ?recipient public))))
	)

	; Asymmetrically decrypt unsigned information 
	; Preconditions:
	;		[(o) Addressed in the method]
	; Effects:
	;		(a) the recipient now has the signed info
	;		(b) the info is now at the recipients local drive
	(:operator 
		(!asymmetric-decrypt ?sender ?recipient 
			(encrypted ?info (key ?recipient public))
		) 
		()
		() 
		(	(has ?recipient ?info local-drive digital-file)
		)
	)

    ; How to asymmetrically decrypt signed information 
	;	Preconditions:
	;		(a) the recipient has the encrypted information with own public key
	;			information is signed by some agent's private key
	;		(b) the recipient has the private key for the encryption
	;		(c) the sender has encryption software
    (:method 
		(decrypt-information ?sender ?recipient ?info) ;name
		(
			(has ?recipient (encrypted  (signed ?info (key ?agent private)) 
				(key ?recipient public)))
			(has ?recipient (key ?recipient private))
			(has ?recipient encryption-software)
		)
		(	(!asymmetric-decrypt-signed ?sender ?recipient 
				(signed ?info (key ?agent private)))
		)
    )

	; Asymmetrically decrypt signed information 
	; Preconditions:
	;		[(o) Addressed in method / repeated here for capturing the signing agent.]  
	; Effects:
	;		(a) the recipient now has the signed info in their local drive
	(:operator 
		(!asymmetric-decrypt-signed ?sender ?recipient (signed ?info (key ?agent private))) 
		(	(has ?recipient (encrypted  (signed ?info (key ?agent private)) 
				(key ?recipient public)))
		)
		()
		(	(has ?recipient (signed ?info (key ?agent private)) local-drive digital-file) 
		)
	)
	











	;  #####  ###  #####  #     #    #    ####### #     # ######  #######  #####  
	; #     #  #  #     # ##    #   # #      #    #     # #     # #       #     # 
	; #        #  #       # #   #  #   #     #    #     # #     # #       #       
	;  #####   #  #  #### #  #  # #     #    #    #     # ######  #####    #####  
	;       #  #  #     # #   # # #######    #    #     # #   #   #             # 
	; #     #  #  #     # #    ## #     #    #    #     # #    #  #       #     # 
	;  #####  ###  #####  #     # #     #    #     #####  #     # #######  #####  




  
	;  #####                                  
	; #     # #  ####  #    # # #    #  ####  
	; #       # #    # ##   # # ##   # #    # 
	;  #####  # #      # #  # # # #  # #      
	;       # # #  ### #  # # # #  # # #  ### 
	; #     # # #    # #   ## # #   ## #    # 
	;  #####  #  ####  #    # # #    #  ####  
	
	; How to asymmetrically sign information 
	;	Preconditions:
	;		(a) the signer has a private key
	;		(b) the signer has the information in digital format
	(:method 
		(sign-information ?signer ?info) ;name
		(	(has ?signer (key ?signer private) digital-file) 
			(has ?signer ?info digital-file)
		)
		(	(!asymmetric-sign ?signer ?info (key ?signer private))
		)
	)

	; Asymmetrically sign information 
	;	Preconditions:
	; 		(o) addressed in the method
	; Effects:
	;		(a) the recipient now "has" the signed info in their local drive
	(:operator 
		(!asymmetric-sign ?signer ?info ?key) 
		()
		() 
		(
			(has ?signer (signed ?info (key ?signer private)) local-drive digital-file)
		)
		200 
	  )

    ; you can always skip signing
	(:method 
		(sign-information ?sender ?info) ;name
		()
		((!na)) ; don't do anything
	)


	; #     #                                                              
	; #     # ###### #####  # ###### #  ####    ##   ##### #  ####  #    # 
	; #     # #      #    # # #      # #    #  #  #    #   # #    # ##   # 
	; #     # #####  #    # # #####  # #      #    #   #   # #    # # #  # 
	;  #   #  #      #####  # #      # #      ######   #   # #    # #  # # 
	;   # #   #      #   #  # #      # #    # #    #   #   # #    # #   ## 
	;    #    ###### #    # # #      #  ####  #    #   #   #  ####  #    # 


	; How to verify signed information 
	;	Preconditions:
	;		(a) the recipient has the public key of the signer
	;		(b) the recipient has the signed information (with said key)
	(:method 
		(verify-information ?recipient ?signer ?info) ;name
		(	(has ?recipient (key ?signer public) digital-file) 
			(has ?recipient (signed ?info (key ?signer private)) digital-file)
		)
		(	(!asymmetric-verify ?recipient ?signer 
				(signed ?info (key ?signer private)) (key ?signer public))
		)
	)

	; Asymmetrically sign information 
	;	Preconditions:
	;		[(o) addressed in the method]
	; Effects:
	;		(a) the recipient has authenticated the information wrt. signer, 
	;				i.e. it is not written by somebody else.
	;		(b) the signer cannot repudiate the information to the recipient 
	;				(i.e. claim they did not sign it)
	(:operator 
		(!asymmetric-verify ?recipient ?signer (signed ?info (key ?signer private)) 
			(key ?signer public)) 
		()
		() 
		(	(authenticated ?recipient ?signer ?info)
			(cannot-repudiate ?signer ?info ?recipient)
		)
	)

	; Verification may not be needed
	(:method 
		(verify-information ?recipient ?signer ?info) ;name
		()
		((!na)) ; don't do anything
	)








  
  
	; #    #                 #     #                                                               
	; #   #  ###### #   #    ##   ##   ##   #    #   ##    ####  ###### #    # ###### #    # ##### 
	; #  #   #       # #     # # # #  #  #  ##   #  #  #  #    # #      ##  ## #      ##   #   #   
	; ###    #####    #      #  #  # #    # # #  # #    # #      #####  # ## # #####  # #  #   #   
	; #  #   #        #      #     # ###### #  # # ###### #  ### #      #    # #      #  # #   #   
	; #   #  #        #      #     # #    # #   ## #    # #    # #      #    # #      #   ##   #   
	; #    # ######   #      #     # #    # #    # #    #  ####  ###### #    # ###### #    #   #   

  
	;    #####                                            
	; #     # ###### #    # ###### #####    ##   #      
	; #       #      ##   # #      #    #  #  #  #      
	; #  #### #####  # #  # #####  #    # #    # #      
	; #     # #      #  # # #      #####  ###### #      
	; #     # #      #   ## #      #   #  #    # #      
	;  #####  ###### #    # ###### #    # #    # ###### 


	; How to manage keys between sender and recipient:
	; 	Option 1: Create all possible kinds of keys
	(:method 
		(manage-keys ?sender ?recipient) ;name
		()
		(	(create-and-share-asymmetric-keys ?sender ?recipient)
			(create-and-share-asymmetric-keys ?recipient ?sender)
			(create-and-share-symmetric-keys ?sender ?recipient)
		)
    )

	; How to manage keys between sender and recipient:
	; 	Option 2: Do nothing
	(:method 
		(manage-keys ?sender ?recipient) ;name
		()
		((!na))
	)

	;How to install encryption software: maybe you don't have to. 
	(:method 
		(install-encryption-software ?user)  ;name
		((has ?user encryption-software))
		((!na))
    )

	;How to install encryption software: just do it
	(:method 
		(install-encryption-software ?user)  ;name
		()
		((!install-encryption-software ?user))
    )
    
	; Asymmetrically sign information 
	;	Preconditions:
	;		None
	; Effects:
	;		(a) encryption software is now present
	(:operator 
		(!install-encryption-software ?user) 
		()
		() 
		((has ?user encryption-software))
		1000 ;heavy cost if we have to do this
	)
  
  
	;  #####                                                   
	; #     # #   # #    # #    # ###### ##### #####  #  ####  
	; #        # #  ##  ## ##  ## #        #   #    # # #    # 
	;  #####    #   # ## # # ## # #####    #   #    # # #      
	;       #   #   #    # #    # #        #   #####  # #      
	; #     #   #   #    # #    # #        #   #   #  # #    # 
	;  #####    #   #    # #    # ######   #   #    # #  ####  
    
  
	; ****************************
	; * Symmetric Key management *
	; ****************************
 
  
	; How to create and share symmetric keys
	; Operations:
	;	(a) Generate the key
	;	(b) Share the key
	; 	No encryption software needed for symmetric cryptography
	(:method 
		(create-and-share-symmetric-keys ?sender ?recipient) ;name
		()
		(	(!generate-symmetric-key ?sender ?recipient)
			(share-key ?sender ?recipient))
    )

	; How to create and share symmetric keys
	; Operations:
    ; 	Do nothing - not needed.
	(:method   
		(create-and-share-symmetric-keys ?sender ?recipient) ;name
		()
		((!na))
    )
  
	; How to create and share symmetric keys between two users
	; Precondition:
	;	(a) none
	; Operations:
	; 	(a) The user has the shared key 
	;	(b) the key is dictatable
	(:operator 
		(!generate-symmetric-key ?user1 ?user2) 
		()
		() 
		(	(has ?user1 (key ?user1 ?user2 shared) local-drive digital-file)
			(has ?user1 (key ?user2 ?user1 shared) local-drive digital-file)
			(is (key ?user1 ?user2 shared) dictatable)
		)
		200
	)

	; How to share a shared key 
	; Precondition:
	;	(a) The sender has the key
	; Operations:
	;	(a) The sender may need to transform the key
	; 	(b) The sender sends the key
	;	(c) The recipient may need to perform another transformation of the key
	(:method 
		(share-key ?sender ?recipient) ;name
		(	(has ?sender (key ?sender ?recipient shared)))
		(	(transform ?sender (key ?sender ?recipient shared))
			(send-info ?sender ?recipient (key ?sender ?recipient shared))
			(transform ?recipient (key ?sender ?recipient shared))
		)
	)



	;    #                                                            
	;   # #    ####  #   # #    # #    # ###### ##### #####  #  ####  
	;  #   #  #       # #  ##  ## ##  ## #        #   #    # # #    # 
	; #     #  ####    #   # ## # # ## # #####    #   #    # # #      
	; #######      #   #   #    # #    # #        #   #####  # #      
	; #     # #    #   #   #    # #    # #        #   #   #  # #    # 
	; #     #  ####    #   #    # #    # ######   #   #    # #  ####  
    
	; ****************************
	; * Asymmetric Key management *
	; ****************************

	; How to create and share asymmetric keys
	; Operations:
	;	(a) Install enrcyption software to both sender and 
	;	(b) ...recipient;
	;	(c) Generate the keys
	;	(d) Sender shares the public key ["sender" of the key]
	(:method 
		(create-and-share-asymmetric-keys ?sender ?recipient) ;For encryption
		()
		(	(install-encryption-software ?sender) 
			(install-encryption-software ?recipient) 
			(generate-asymmetric-keys ?sender)
			(share-public-key ?sender ?recipient)
		)
    )

	; There is the choice to not do it
	(:method   
		(create-and-share-asymmetric-keys ?sender ?recipient) ;name
		()
		((!na))
	)

	; There is a choice not to do it (e.g. keys are already there just need sharing)
	(:method   
		(generate-asymmetric-keys ?user) ;name
		(	(has ?user (key ?user public)) 
			(has ?user (key ?user private)) 
		)
		((!na))
    )

	; How to generate asymmetric keys
	; Operations:
	;	(a) just do so
	(:method   
		(generate-asymmetric-keys ?user) ;name
		()
		((!generate-asymmetric-keys ?user))
    )

	; How to generate asymmetric keys
	; Precondition:
	;	(a) none
	; Operations:
	; 	(a) The user has the public key in their local-drive
	; 	(a) The user has the private key in their local-drive
	(:operator 
		(!generate-asymmetric-keys ?user) 
		((has ?user encryption-software)) 
		() 
		(	(has ?user (key ?user public) local-drive digital-file)
			(has ?user (key ?user private) local-drive digital-file) 
		)
		500
	)
  
  	; How to create and share a public key
	; Precondition:
	;	(o) The key exists
	; Operations:
	;	(a) perform the needed transformations
	;	(b) send the key
	;	(c) recipient may need to perform transformations as well.
	(:method 
		(share-public-key  ?sender ?recipient) ;name
		(	(has ?sender (key ?sender public) local-drive digital-file)
		)
		(	(transform ?sender (key ?sender public))
			(send-info ?sender ?recipient (key ?sender public))
			(transform ?recipient (key ?sender public))
		)
    )



	; #     #    #    ### #     # 
	; ##   ##   # #    #  ##    # 
	; # # # #  #   #   #  # #   # 
	; #  #  # #     #  #  #  #  # 
	; #     # #######  #  #   # # 
	; #     # #     #  #  #    ## 
	; #     # #     # ### #     # 


	; Sign and/or encrypt
	; Precondition:
	;	(a) none
	; Operations:
	;	Perform any of sign, encrypt or sign and encrypt
	(:method 
       (security-en ?sender ?recipient ?info) ;name
       ()
       (
	    (sign-information ?sender ?info)
	    (encrypt-information ?sender ?recipient ?info)
	   )
    )

	; Sign and/or encrypt
	; Precondition:
	;	(a) none
	; Operations:
	;	Perform any of sign, encrypt or sign and encrypt
	(:method 
       (security-en ?sender ?recipient ?info) ;name
       ()
       (
	    (encrypt-information ?sender ?recipient ?info)
	   )
    )

	; Sign and/or encrypt
	; Precondition:
	;	(a) none
	; Operations:
	;	Perform any of sign, encrypt or sign and encrypt
	(:method 
       (security-en ?sender ?recipient ?info) ;name
       ()
       (
	    (sign-information ?sender ?info)
	   )
    )


	; Decrupt and/or verify
	; Precondition:
	;	(a) none
	; Operations:
	;	Perform any of decrypt, verify signature, or encrypt and verify signature
	(:method 
       (security-de ?sender ?recipient ?info) ;name
       ()
       (
		(decrypt-information ?sender ?recipient ?info)
		(verify-information ?recipient ?sender ?info)
	   )
    )

	; Decrupt and/or verify
	; Precondition:
	;	(a) none
	; Operations:
	;	Perform any of decrypt, verify signature, or encrypt and verify signature
	(:method 
       (security-de ?sender ?recipient ?info) ;name
       ()
       (
		(decrypt-information ?sender ?recipient ?info)
	   )
    )

	; Decrupt and/or verify
	; Precondition:
	;	(a) none
	; Operations:
	;	Perform any of decrypt, verify signature, or encrypt and verify signature
	(:method 
       (security-de ?sender ?recipient ?info) ;name
       ()
       (
		(verify-information ?recipient ?sender ?info)
	   )
    )
	
	;++++++++++++++ 
	;+ ** MAIN ** +
	;++++++++++++++ 
	(:method 
       (transmit-information ?sender ?recipient ?info) ;name
       ()
       (:ordered
	    (transform ?sender ?info) ;if needed
	    (security-en ?sender ?recipient ?info)
	    (send-info ?sender ?recipient ?info)
		(security-de ?sender ?recipient ?info)
		(transform ?receipient ?info) ;if needed
		)
    )
	
	

	;    #                                        #######                             
	;   # #   ##### #####   ##    ####  #    #       #    #####  ###### ######  ####  
	;  #   #    #     #    #  #  #    # #   #        #    #    # #      #      #      
	; #     #   #     #   #    # #      ####         #    #    # #####  #####   ####  
	; #######   #     #   ###### #      #  #         #    #####  #      #           # 
	; #     #   #     #   #    # #    # #   #        #    #   #  #      #      #    # 
	; #     #   #     #   #    #  ####  #    #       #    #    # ###### ######  ####  


	; Attack Axiom - intercepting information is possible if:
	(:- (ConBreached ?sender ?recipient ?info)
			;... information or secrete keys are shared publicly
			(shared-publicly ?info)
			(shared-publicly (signed ?info (key ?any1 ?any2)))
			(shared-publicly (key ?sender private))
			(shared-publicly (key ?sender ?recipient shared))
			
			;... information or secrete keys pass through a hacked network
			(and (is-compromised network) 
				 (pass-through-data-network ?info)) 
			(and (is-compromised network) 
				 (pass-through-data-network (signed ?info (key ?any1 ?any2)))) 
			(and (is-compromised network) 
				 (pass-through-data-network (key ?anyone private))) 
			(and (is-compromised network) 
				 (pass-through-data-network (key ?anyone ?anyoneelse shared)))
				 
			;... information or secrete keys rest in a compromized location
			(and (is-compromised ?recipient ?location) 
				 (has ?recipient ?info ?location ?someformat))
			(and (is-compromised ?recipient ?location) 
				 (has ?recipient (signed ?info (key ?any1 ?any2)) ?location ?someformat))
			(and (is-compromised ?recipient ?location) 
				 (has ?recipient (key ?anyone private) ?location ?someformat))
			(and (is-compromised ?recipient ?location) 
				 (has ?recipient (key ?anyone ?anyoneelse shared) ?location ?someformat))
				 
			;... information or secrete keys pass through a bugged phone
			(and (or (is-bugged ?sender) (is-bugged ?recipient)) 
					 (shared-by-phone ?sender ?recipient ?info))
			(and (or (is-bugged ?sender) (is-bugged ?recipient)) 
					 (shared-by-phone ?sender ?recipient (key ?anyone private)))
			(and (or (is-bugged ?sender) (is-bugged ?recipient)) 
					 (shared-by-phone ?sender ?recipient (key ?anyone ?anyoneelse shared)))
	)



	; Attack Axiom - tampering with information is possible if:
	(:- (IntBreached ?sender ?recipient ?info)
			;... information or secrete keys are shared publicly
			(shared-publicly ?info)
			(shared-publicly (signed ?info (key ?any1 ?any2)))
			(shared-publicly (key ?sender private))
			(shared-publicly (key ?sender ?recipient shared))
			
			;... information or secrete keys pass through a hacked network
			(and (is-compromised network) 
				 (pass-through-data-network ?info)) 
			(and (is-compromised network) 
				 (pass-through-data-network (key ?anyone private))) 
			(and (is-compromised network) 
				 (pass-through-data-network (key ?anyone ?anyoneelse shared)))
				 
			;... information or secrete keys rest in a compromized location
			(and (is-compromised ?recipient ?location) 
				 (has ?recipient ?info ?location ?someformat))
			(and (is-compromised ?recipient ?location) 
				 (has ?recipient (key ?anyone private) ?location ?someformat))
			(and (is-compromised ?recipient ?location) 
				 (has ?recipient (key ?anyone ?anyoneelse shared) ?location ?someformat))
	)

	; Negative Attack Axiom - Authentication is successful if:
	(:- (AuthSuccessful ?sender ?recipient ?info)
		(and	(authenticated ?recipient ?sender ?info)
			(not (IntBreached ?sender ?recipient ?info))
		)
	)
	
	;
	(:- (Repudiate ?agent ?info)
		(not (AuthSuccessful ?agent ?recipient ?info))
	)


	

	; ######                                         
	; #     #  ####  #    #   ##   # #    #          
	; #     # #    # ##  ##  #  #  # ##   #          
	; #     # #    # # ## # #    # # # #  #          
	; #     # #    # #    # ###### # #  # #          
	; #     # #    # #    # #    # # #   ##          
	; ######   ####  #    # #    # # #    #          
    
	;   #####                                         
	;  #     # #####  ######  ####  # ###### #  ####  
	;  #       #    # #      #    # # #      # #    # 
	;   #####  #    # #####  #      # #####  # #      
	;        # #####  #      #      # #      # #      
	;  #     # #      #      #    # # #      # #    # 
	;   #####  #      ######  ####  # #      #  ####  



    (:method 
		(sendInvoice ?sender ?recipient) ;name
		() ; precondition
			(:ordered
				(manage-keys ?sender ?recipient)
				(transmit-information ?sender ?recipient invoice)
				(final)
			)
    )



    (:method 
    (final) ;name
	(
	   
		; ++++++++++++++++++++++++++++++++++++++++++
		; + D O M A I N    R E Q U I R E M E N T S +
		; ++++++++++++++++++++++++++++++++++++++++++
		(can-read contractor invoice)
		
	   
		; ++++++++++++++++++++++++++++++++++++++++++++++
		; + S E C U R I T Y    R E Q U I R E M E N T S +
		; ++++++++++++++++++++++++++++++++++++++++++++++
		(not (ConBreached supplier contractor invoice))
		(AuthSuccessful supplier contractor invoice)
		;(not (Repudiate supplier invoice))
		
		(not 	(has supplier (key supplier contractor shared) local-drive digital-file))
	)
		(	(!done))
    )


))




	; ######                                                #####                       
	; #     # #####   ####  #####  #      ###### #    #    #     # #####  ######  ####  
	; #     # #    # #    # #    # #      #      ##  ##    #       #    # #      #    # 
	; ######  #    # #    # #####  #      #####  # ## #     #####  #    # #####  #      
	; #       #####  #    # #    # #      #      #    #          # #####  #      #      
	; #       #   #  #    # #    # #      #      #    #    #     # #      #      #    # 
	; #       #    #  ####  #####  ###### ###### #    #     #####  #      ######  ####  
 
	(defproblem problem1 sec
		(
		; +++++++++++++++++++++++++++++++++++++++++
		; + D O M A I N    A S S U M P T I O N S  +
		; +++++++++++++++++++++++++++++++++++++++++
	   
		(has contractor order local-drive digital-file)
		(has supplier invoice local-drive digital-file)

		(allow email)
		;(allow sms)
		;(allow in-person)
		(allow phonecall)

		(has contractor supplier email-address)
		(has supplier contractor email-address)
		(has contractor supplier phone-number)
		(has supplier contractor phone-number)
		;(can-meet contractor supplier)
		;(can-meet supplier contractor)
   
		; +++++++++++++++++++++++++++++++++
		; +   V U L N E R A B I L I T Y   +     
		; +     A S S U M P T I O N S     +
		; +++++++++++++++++++++++++++++++++
		(is-compromised network)
		(is-compromised contractor mailbox)


	) 

	
	(:ordered
		(sendInvoice supplier contractor)
	)
	
	
) ; end of problem specification


; Find plans while optimizing for cost
(find-plans 'problem1 :verbose :plans :optimize-cost t)
 

  
