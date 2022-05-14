# Overview
The following is the HTN SHOP2 sample specification accompanying our MODELS 2022 submission *"Towards automating security requirements implementation using secure workflow patterns"*. The listing is presented at the bottom of this page and can also be downloaded as a LISP file in the repository. It contains: (a) workflow patterns for securely transmitting information between two actors using various communication channels and utilizing cryptographic primitives, (b) attack trees for confidentiality and integrity. In later sections, we use these assets to reason with various security requirements and vulnerability assumptions. 

The presented formalization here is much more complex and uses different conventions than the ones in the paper (e.g. second order LISP-like terms are extensively used), without, however, departing from the main ideas and vision in the paper. The formalization can be seen as one of the many possible that can be devised for solving the same problem domain (securely transferring documents between two parties). The formalization of choice is a result of balancing between expressiveness, exact reasoning needs (e.g. do we need to reason about many different channels?), and computational efficiency and is a central piece of our future research agenda.

The listing, found at the bottom, can be compiled and used as-is by the SHOP2 planner. Installation instructions are provided below.


# The Model

## Key aspects
The specification focusses on the exchange of information between two parties making certain assumptions on the devices and media in which the information is stored, and the computational devices that the participants use. The possibilities are by no means meant to be exhaustive but rather to provide an illustration of the reasoning framework that is proposed. 

## Computational Devices
Participants in the workflows are assumed to have access to the following devices:
* A PC or other computer connected to the internet. The PC is the only devices where cryptographic functions can be executed.
* A mobile phone, capable of sending text messages with file attachments. Actors can connect their phone to their PC to exchange files. 
* A printer and a scanner (with no handwriting recognition). 
* 
## Formats and Media

Information is at any point in time available with an actor. A special predicate is used to signify this:
```lisp
(has ?agent ?info ?medium ?format)
```
While ``` ?agent ``` and ```?info``` can be anything, ```?medium``` and ```?format``` are restricted as follows:

Possibilities for medium:
* Local-drive: meaning the hard-drive of the PC
* shared-folder: implies that the file exists also in the cloud and accessible for anyone with access to the cloud account
* mailbox: the inbox or outbox of an agent’s email account, which is assumed to reside both on a server and on a local copy.
* phone: any part of the agent’s smartphone (e.g. text messages, file-system or email app), such that hacking the phone implies full access to that location.
* USB: shorthand for any portable digital storage device, including e.g. CDs, DVDs or other media.
* Physical: any physical location in which an agent has access: e.g., their pocket or their desk. 

Possibilities for format:
* digital-file
* paper which can be either printed (thus, OCR-able) or handwritten.

Information can be scanned, typed-up and copied from one machine to another. Printing information is omitted for simplicity. When appropriate, we assume that users will naturally expand the attack by copying the information from one medium to the other for example:
* Information in shared-drive will eventually sync to the local-drive
* Information in the e-mailbox, will be copied to local-drive.


## Transferring information
Information can be transferred in any of the following ways:
* Email.
* SMS, i.e., text messaging, which is assumed to also support attachments.
* Phone-call oral exchange, whereby one actor is calling another and offers the information verbally. The other actor is assumed to jot down the information manually in their physical space. 
* In person exchange, whereby one actor visits the physical space of another actor and delivers the information in paper or digital format (e.g. USB key).
* In person oral exchange, like phone-call oral exchange but resulting from a visit to another persons space.

## Encryption and Decryption Methods

Encryption can be _symmetric_ or _asymmetric_. In the former case the participants exchange a shared key and use their document viewer or word processor to protect/encrypt the document with the key. As such no extra software is required. However, the shared key needs to be exchanged securely. 

For asymmetric encryption public/private key pairs need to be generated and the public parts exchanged in a way that is not necessarily secured. We however assume that the standard versions of document viewers and processors do not trivially support public key cryptography. As such, specialized software needs to be installed for such, such as for example [OpenPGP](https://www.openpgp.org/).

## Digital Signatures
Digital signing is assumed to be asymmetric through the use of third-party software such as [OpenPGP](https://www.openpgp.org/). It is further assumed that signing and encryption take place independently and in this order when both are needed. 

## Key management
Key management is a step that generally precede encryption and/or signing, and involves key generation and sharing. The sharing of keys follows the same methods as the sharing of any other information. However, advanced key establishment protocols that may need specialized software or synchronous communication are not currently included as methods, due to being unrelated to the context and examples of use we are considering here. Thus, shared key exchange, which is sensitive information, must take place using a channel that is assumed to be secure (e.g. in person exchange, a phone call or other method) depending on the *vulnerability assumptions* in effect. 

## Attack Trees
Attack trees are simple axioms connecting a high-level characterization of the attack (the negation of a security requirement) with a logical formula describing conditions under which the attack is accomplished, hence the security requirement successfully breached. Notice that the components of the formula appear in any of: effects and preconditions of operations and/or methods, vulnerability assumptions or domain assumptions. 

## Domain and Security Requirements
As mentioned in the paper, a special action is added in the domain specification for the purpose of enforcing its precondition. This is due to the fact that SHOP2’s problem specification is written in the form of a top level method rather than a goal state. Thus, a method we call ```final``` is introduced and security and other domain requirements are added as preconditions. Successful fulfilment of these preconditions allows the planner to execute “done”, a dummy unconditional action.

## Problem Specification

### Domain and Vulnerability Assumptions
The domain and vulnerability assumptions are part of the problem specification and specifically the description of the _initial state_. THus:

```lisp
	(defproblem problem1 sec
		(
		; +++++++++++++++++++++++++++++++++++++++++
		; + D O M A I N    A S S U M P T I O N S  +
		; +++++++++++++++++++++++++++++++++++++++++
	   
		(has contractor order local-drive digital-file)
		(has supplier invoice local-drive digital-file)
	
		(allow email)
		(allow phonecall)

		(has contractor supplier email-address)
		(has supplier contractor email-address)
		(has contractor supplier phone-number)
		(has supplier contractor phone-number)
	
		; +++++++++++++++++++++++++++++++++
		; +   V U L N E R A B I L I T Y   +     
		; +     A S S U M P T I O N S     +
		; +++++++++++++++++++++++++++++++++
		(is-compromised network)
		(is-compromised contractor mailbox)

	) 
	
	;...  main problem below
```

### Main Problem Definition
Problem definition is based on the specification of the top-level method (in our case ```transmit-information```) preceded by a ```manage-keys``` call and followed by ```final```, which must be achieved in any successful plan. Obviously, the three constituent methods can be further abstracted into a top level method.

```lisp

	; ... initial state above
	
	(:ordered
		(manage-keys doctor patient)
		(transmit-information doctor patient proof-of-visit)
		(final)
	)
```

# Running 
To identify plans, SHOP2 requires running 
```lisp
(find-plans 'problem1 :verbose :plans :optimize-cost t)
```

(Please see below for rough installation instructors.)

## Running Example

Let us now explore the example of the interaction between the supplier and the contractor as seen in the paper. As stated above, the example here is much more elaborate than the one that has been presented in the paper for the interest of simplicity.

Recall that the interaction is that the contractor places an order to the supplier, who, in turn issues an invoice to be sent to the contractor.

### Case 1 – No security requirements and no vulnerability assumptions.

We start with the scenario in which no security requirements are given. Thus in the final method we have:

```lisp
    (:method 
    (final) 
	(	; ++++++++++++++++++++++++++++++++++++++++++
		; + D O M A I N    R E Q U I R E M E N T S +
		; ++++++++++++++++++++++++++++++++++++++++++
		
		(can-read contractor invoice)
		
	   
		; ++++++++++++++++++++++++++++++++++++++++++++++
		; + S E C U R I T Y    R E Q U I R E M E N T S +
		; ++++++++++++++++++++++++++++++++++++++++++++++

		;empty
	)
		(done))
    )
```

... and the problem definition is ...

```lisp
(defproblem problem1 sec
	(
		; +++++++++++++++++++++++++++++++++++++++++
		; + D O M A I N    A S S U M P T I O N S  +
		; +++++++++++++++++++++++++++++++++++++++++
	   
		(has supplier invoice local-drive digital-file)

		(allow email)
		(allow sms)
		(allow phonecall)

		(has contractor supplier email-address)
		(has supplier contractor email-address)
		(has contractor supplier phone-number)
		(has supplier contractor phone-number)

   
		; +++++++++++++++++++++++++++++++++
		; +   V U L N E R A B I L I T Y   +     
		; +     A S S U M P T I O N S     +
		; +++++++++++++++++++++++++++++++++
		
		;empty
	)
	
	(:ordered
		(manage-keys supplier contractor)
		(transmit-information supplier contractor invoice)
		(final)
	)
	
) ; end of problem specification
```

In such case, the planner will not be constrained in any way to produce the cheapest possible plan, which may involve the simple transfer of the document from sender to recipient in plaintext, thus plan:

```text
Defining problem PROBLEM1 ...
---------------------------------------------------------------------------
Problem #<SHOP3::PROBLEM PROBLEM1> with :WHICH = :FIRST, :VERBOSE = :PLANS, OPTIMIZE-COST = T

Totals: Plans Mincost Maxcost Expansions Inferences  CPU time  Real time
           1  -178.0  -178.0        392       6902     0.125      0.128

Plans:
(((!NA) (!NA) (!NA) (!NA) (!NA) (!NA) (!EMAIL SUPPLIER CONTRACTOR INVOICE)
  (!NA) (!NA) (!NA) (!DONE)))
```

When looking at the plan we discard all the (!NA) actions, which simply signify optional actions (e.g. key creation and exchange, encryption, etc.) that were not chosen. What remains is a simple email action of the invoice from the supplier to the contractor, without any security steps. Notice also the CPU time and inferences it takes to generate the plan, to compare with the examples that follow.


### Case 2 – Invoice confidential.

Let us now assume that we specify a confidentiality requirement: the contractor wants to be able to ensure that has not been read by unauthorized parties. We state this requirement through a negated attack:

```lisp
		; ++++++++++++++++++++++++++++++++++++++++++++++
		; + S E C U R I T Y    R E Q U I R E M E N T S +
		; ++++++++++++++++++++++++++++++++++++++++++++++

		(not (intercept-successful supplier contractor invoice))
```

However, we do not add any vulnerability assumptions. The planner will return the exact same plan:

```text
Defining problem PROBLEM1 ...
---------------------------------------------------------------------------
Problem #<SHOP3::PROBLEM PROBLEM1> with :WHICH = :FIRST, :VERBOSE = :PLANS, OPTIMIZE-COST = T

Totals: Plans Mincost Maxcost Expansions Inferences  CPU time  Real time
           1  -178.0  -178.0        392       7208     0.109      0.111

Plans:
(((!NA) (!NA) (!NA) (!NA) (!NA) (!NA) (!EMAIL SUPPLIER CONTRACTOR INVOICE)
  (!NA) (!NA) (!NA) (!DONE)))
```

That is, there will be no security steps when the attackers are not assumed to engage in any attack. If we do assume we protect against certain attacks, such as for example, compromised mailboxes and networks then we need to add the corresponding vulnerability assumptions:


```lisp
		; +++++++++++++++++++++++++++++++++
		; +   V U L N E R A B I L I T Y   +     
		; +     A S S U M P T I O N S     +
		; +++++++++++++++++++++++++++++++++

		(is-compromised network)
		(is-compromised contractor mailbox)
```

Then the planner will resort to encryption:

```text
Defining problem PROBLEM1 ...
---------------------------------------------------------------------------
Problem #<SHOP3::PROBLEM PROBLEM1> with :WHICH = :FIRST, :VERBOSE = :PLANS, OPTIMIZE-COST = T

Totals: Plans Mincost Maxcost Expansions Inferences  CPU time  Real time
           1   265.0   265.0      35122     841859     9.672      9.659

Plans:
(((!NA) (!NA) (!GENERATE-SYMMETRIC-KEY SUPPLIER CONTRACTOR) (!NA)
  (!BY-PHONECALL-EXCHANGE SUPPLIER CONTRACTOR (KEY SUPPLIER CONTRACTOR SHARED))
  (!TYPE-UP CONTRACTOR (KEY SUPPLIER CONTRACTOR SHARED)) (!NA) (!NA)
  (!SYMMETRIC-ENCRYPT SUPPLIER CONTRACTOR INVOICE
   (KEY SUPPLIER CONTRACTOR SHARED))
  (!EMAIL SUPPLIER CONTRACTOR
   (ENCRYPTED INVOICE (KEY SUPPLIER CONTRACTOR SHARED)))
  (!SYMMETRIC-DECRYPT CONTRACTOR SUPPLIER INVOICE) (!NA) (!NA) (!DONE)))

``` 

The plan says that the supplier now needs to generate a key, call the contractor to share the key and then symmetrically encrypt the document before sending it by email. In practice, this may means that the PDF or DOC is protected with a password within the corresponding document editing or word processing tools; and the password is exchanged via a channel for which no vulnerability has been assumed. The planner avoids asymmetric encryption which is more expensive as it requires installation of specialized software.

### Case 3 – Contractor wants to authenticate the invoice.

Let us now assume that we specify an authenticity requirement: the contractor does not want unauthorised users to read the invoice. We then consider the following security requriements while keeping all else as-is:

```lisp
		; ++++++++++++++++++++++++++++++++++++++++++++++
		; + S E C U R I T Y    R E Q U I R E M E N T S +
		; ++++++++++++++++++++++++++++++++++++++++++++++

		(authenticated contractor supplier invoice)
```

The plan that will return now is different:

```text
Defining problem PROBLEM1 ...
---------------------------------------------------------------------------
Problem #<SHOP3::PROBLEM PROBLEM1> with :WHICH = :FIRST, :VERBOSE = :PLANS, OPTIMIZE-COST = T

Totals: Plans Mincost Maxcost Expansions Inferences  CPU time  Real time
           1  2544.0  2544.0      10299     225959     2.625      2.624

Plans:
(((!INSTALL-ENCRYPTION-SOFTWARE SUPPLIER)
  (!INSTALL-ENCRYPTION-SOFTWARE CONTRACTOR)
  (!GENERATE-ASYMMETRIC-KEYS SUPPLIER) (!NA)
  (!EMAIL SUPPLIER CONTRACTOR (KEY SUPPLIER PUBLIC)) (!NA) (!NA) (!NA) (!NA)
  (!ASYMMETRIC-SIGN SUPPLIER INVOICE (KEY SUPPLIER PRIVATE)) (!NA)
  (!EMAIL SUPPLIER CONTRACTOR (SIGNED INVOICE (KEY SUPPLIER PRIVATE))) (!NA)
  (!ASYMMETRIC-VERIFY CONTRACTOR SUPPLIER
   (SIGNED INVOICE (KEY SUPPLIER PRIVATE)) (KEY SUPPLIER PUBLIC))
  (!NA) (!DONE)))
```

In this case the supplier will digitally sign the document prior to sending it to the contractor. However, encryption software needs to be installed (e.g. [OpenPGP](https://www.openpgp.org/software/kleopatra/)) and the supplier needs to generate a public-private key pair and share the public one. It does not matter that the public key goes through a compromised medium (email).


### Case 4 – Authenticate _and_ encrypt the invoice.

Let us finally assume that both authentication and encryption are needed:

```lisp
		; ++++++++++++++++++++++++++++++++++++++++++++++
		; + S E C U R I T Y    R E Q U I R E M E N T S +
		; ++++++++++++++++++++++++++++++++++++++++++++++

		(authenticated contractor supplier invoice)
		(not (intercept-successful supplier contractor invoice))
```

Then we will get the following plan:

```text
Defining problem PROBLEM1 ...
---------------------------------------------------------------------------
Problem #<SHOP3::PROBLEM PROBLEM1> with :WHICH = :FIRST, :VERBOSE = :PLANS, OPTIMIZE-COST = T

Totals: Plans Mincost Maxcost Expansions Inferences  CPU time  Real time
           1  2788.0  2788.0      38165     856093    10.047     10.047

Plans:
(((!INSTALL-ENCRYPTION-SOFTWARE SUPPLIER)
  (!INSTALL-ENCRYPTION-SOFTWARE CONTRACTOR)
  (!GENERATE-ASYMMETRIC-KEYS SUPPLIER) (!NA)
  (!EMAIL SUPPLIER CONTRACTOR (KEY SUPPLIER PUBLIC)) (!NA) (!NA)
  (!GENERATE-SYMMETRIC-KEY SUPPLIER CONTRACTOR) (!NA)
  (!BY-PHONECALL-EXCHANGE SUPPLIER CONTRACTOR (KEY SUPPLIER CONTRACTOR SHARED))
  (!TYPE-UP CONTRACTOR (KEY SUPPLIER CONTRACTOR SHARED)) (!NA)
  (!ASYMMETRIC-SIGN SUPPLIER INVOICE (KEY SUPPLIER PRIVATE))
  (!SYMMETRIC-ENCRYPT-SIGNED SUPPLIER (SIGNED INVOICE (KEY SUPPLIER PRIVATE))
   (KEY SUPPLIER CONTRACTOR SHARED))
  (!EMAIL SUPPLIER CONTRACTOR
   (ENCRYPTED (SIGNED INVOICE (KEY SUPPLIER PRIVATE))
    (KEY SUPPLIER CONTRACTOR SHARED)))
  (!SYMMETRIC-DECRYPT-SIGNED CONTRACTOR SUPPLIER INVOICE)
  (!ASYMMETRIC-VERIFY CONTRACTOR SUPPLIER
   (SIGNED INVOICE (KEY SUPPLIER PRIVATE)) (KEY SUPPLIER PUBLIC))
  (!NA) (!DONE)))

```

The above plan suggests that the document will be signed using a public key exchanged by email and then symmetrically encrypted, with key exchanged over a phone call, before it is sent over by email for decryption and verification.

One may doubt, however, that this is the most convenient way of doing it. Indeed, the specification does not have a fine-tuned cost scheme at this point that would recognize that, since asymmetric encryption software has been installed for the signatures, encryption may as well be asymmetric, saving the phone call for the shared key exchange. Even then, though, the analysts can simply artificially disallow symmetric encryption, e.g. through an ad-hoc precondition or assumptions such as:

```lisp
		; ++++++++++++++++++++++++++++++++++++++++++++++
		; + S E C U R I T Y    R E Q U I R E M E N T S +
		; ++++++++++++++++++++++++++++++++++++++++++++++

		... [as above]
		(not (has supplier (key supplier contractor shared) local-drive digital-file)
```
So now, we demand that at no point is there a shared key generated. The planner will respond as follows:

```text

Defining problem PROBLEM1 ...
---------------------------------------------------------------------------
Problem #<SHOP3::PROBLEM PROBLEM1> with :WHICH = :FIRST, :VERBOSE = :PLANS, OPTIMIZE-COST = T

Totals: Plans Mincost Maxcost Expansions Inferences  CPU time  Real time
           1  3526.0  3526.0     215113    4880945    60.656     60.645

Plans:
(((!INSTALL-ENCRYPTION-SOFTWARE SUPPLIER)
  (!INSTALL-ENCRYPTION-SOFTWARE CONTRACTOR)
  (!GENERATE-ASYMMETRIC-KEYS SUPPLIER) (!NA)
  (!EMAIL SUPPLIER CONTRACTOR (KEY SUPPLIER PUBLIC)) (!NA) (!NA) (!NA)
  (!GENERATE-ASYMMETRIC-KEYS CONTRACTOR) (!NA)
  (!EMAIL CONTRACTOR SUPPLIER (KEY CONTRACTOR PUBLIC)) (!NA) (!NA) (!NA)
  (!ASYMMETRIC-SIGN SUPPLIER INVOICE (KEY SUPPLIER PRIVATE))
  (!ASYMMETRIC-ENCRYPT SUPPLIER CONTRACTOR
   (SIGNED INVOICE (KEY SUPPLIER PRIVATE)) (KEY CONTRACTOR PUBLIC))
  (!EMAIL SUPPLIER CONTRACTOR
   (ENCRYPTED (SIGNED INVOICE (KEY SUPPLIER PRIVATE)) (KEY CONTRACTOR PUBLIC)))
  (!ASYMMETRIC-DECRYPT-SIGNED SUPPLIER CONTRACTOR
   (SIGNED INVOICE (KEY SUPPLIER PRIVATE)))
  (!ASYMMETRIC-VERIFY CONTRACTOR SUPPLIER
   (SIGNED INVOICE (KEY SUPPLIER PRIVATE)) (KEY SUPPLIER PUBLIC))
  (!NA) (!DONE)))
```

... which involves asymmetric signing, encryption, emailing, decryption and verification. 


# Installation Instructions (Windows)

* Install a list in your system. We have tryied it with [Steel Bank Common Lisp](http://www.sbcl.org/).
* Install SHOP3 following direction [in the github page](https://github.com/shop-planner/shop3). We used the quicklisp installation option solution successfully.
* Save the listing below in a .lisp file, such as ``` Example.lisp```
* Once in sbcl and SHOP3 is loaded (e.g. through a ```(load "~/init.lisp")```, run ```(load "Example.lisp")```
* You can make changes to the .lisp file and reload as above; definitions will be replaced.

# The Listing

```lisp
(in-package :shop-user)
; This extremely simple example shows some of the most essential
;   features of SHOP2.

(defdomain sec (
	
	
(:operator (!na) () () () -20)
(:operator (!done) () () ())	
(:operator (!no-need-for-keys) () () () -500)

    ; #                                  
   ; # #   #    # #  ####  #    #  ####  
  ; #   #   #  #  # #    # ##  ## #      
 ; #     #   ##   # #    # # ## #  ####  
 ; #######   ##   # #    # #    #      # 
 ; #     #  #  #  # #    # #    # #    # 
 ; #     # #    # #  ####  #    #  ####  

	
   ; General Axioms 
   
	(:- (has ?agent ?info) (has ?agent ?info ?someLocation ?someformat))
   
    (:- (has ?agent ?info ?someformat) (has ?agent ?info ?someLocation ?someformat))
   
    (:- (has ?agent ?info) (is-at ?agent ?x ?info)) ;deprecated

	(:- (can-read ?agent ?info) (and (has ?agent ?info)
								)	 (not ((has ?agent ?info usb ?someformat)))
	)

	(:- (can-read ?agent ?info) ((has ?agent ?info))
	)

	(:- (can-read ?agent ?info) (has ?agent (signed ?info (key ?whatever private))))

	(:- (can-verify-authenticity ?agent ?author ?info) 
	    (and 
			(has ?agent ?info) 
			(has ?agent (signed ?info (key ?author private)))
			(has ?agent (key ?author public))
		)
	
	)

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
  

  
    ; ******************************
    ; * SEND Information - METHODS *
    ; ******************************

	 
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
			(allow email)
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

 
	;You can meet the person and pass a letter or a usb stick
    (:method 
       (send-information ?sender ?recipient ?info) ;name
	   (	(is-in-person-transmissible ?sender ?recipient ?info)
			(allow in-person)
	   )
       ((in-person-exchange ?sender ?recipient ?info))
    )

    ;You can meet the person and tell them the information
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
 
(:- (has ?agent ?info local-drive ?format) ((has ?agent ?info mailbox ?format))) ;because the agent is assumed to save the document locally
(:- (has ?agent ?info local-drive ?format) ((has ?agent ?info shared-folder ?format))) 
;because the agent is assumed to synch the shared folder with the local one

(:- (has ?someone ?info ?somewhere paper) ((has ?someone ?info ?somewhere printed))) 
(:- (has ?someone ?info ?somewhere paper) ((has ?someone ?info ?somewhere handwritten))) 

(:- (has ?someone ?info processable) ((has ?someone ?info ?somewhere digital-file))) 


; #######                        
; #       #    #   ##   # #      
; #       ##  ##  #  #  # #      
; #####   # ## # #    # # #      
; #       #    # ###### # #      
; #       #    # #    # # #      
; ####### #    # #    # # ###### 
 
    (:- (is-email-transmissible ?sender ?recipient ?info) 
			(and 	
				(has ?sender ?recipient email-address)
				(or	(has ?sender ?info local-drive digital-file)
					(has ?sender ?info mailbox digital-file)
					(has ?sender ?info shared-folder digital-file)
					(has ?sender ?info phone digital-file)
					(has ?sender ?info usb digital-file)
;					(has ?sender ?info physical paper) ;can scan it and/or OCR it
				)
			)
	)
	


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
 
    (:- (is-sms-transmissible ?sender ?recipient ?info) 
			(and 	
				(has ?sender ?recipient phone-number)
				(or	(has ?sender ?info local-drive digital-file) ;transfer
					(has ?sender ?info mailbox digital-file) ;save and transfer
					(has ?sender ?info shared-folder digital-file) ;download and transfer
					(has ?sender ?info phone digital-file) 
					(has ?sender ?info usb digital-file) ;connect digital
;					(has ?sender ?info physical paper) ; scan and transfer
				)
			)
	)

	; When I send an sms/text:
	; (a) the info is in the recepeient's phone
	; (b) the info has-passed through the-mobile-network
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
                                                          

    (:- (is-in-person-transmissible ?sender ?recipient ?info) 
				(and 	
				(or  (can-meet ?sender ?recipient)  (can-meet ?recipient ?sender))
				(or	(has ?sender ?info local-drive digital-file) ;put in USB or print it
					(has ?sender ?info mailbox digital-file) ;put in USB or print it
					(has ?sender ?info shared-folder digital-file) ;download put in USB or print it
					(has ?sender ?info phone digital-file) ;put in USB or print it or print it
					(has ?sender ?info usb digital-file) ; great
					(has ?sender ?info physical paper) ;just carry the document
				)
				)
	)
  
   (:method 
		(in-person-exchange ?sender ?recipient ?info) ;name
		(	(is-in-person-transmissible ?sender ?recipient ?info) 
			(has ?sender ?info ?somemedium digital-file)
		) 
		((!in-person-exchange-digital ?sender ?recipient ?info))
    )

   (:method 
		(in-person-exchange ?sender ?recipient ?info) ;name
		(	(is-in-person-transmissible ?sender ?recipient ?info) 
		) 
		((!in-person-exchange-paper ?sender ?recipient ?info))
    )

   (:operator 
		(!in-person-exchange-digital ?sender ?recipient ?info) 
		(	
			(is-in-person-transmissible ?sender ?recipient ?info)
			(has ?sender ?info ?somemedium digital-file)
		)
		()
		( 	(has ?recipient ?info local-drive digital-file) ;we assume the person will read the content
			(has ?recipient ?info physical digital-file); refers to the presence of a usb on the person's desk
			(shared-in-person ?sender ?recipient ?info)
		)
	)

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

    (:- (is-in-person-orally-transmissible ?sender ?recipient ?info) 
				(and 	
				(or  (can-meet ?sender ?recipient)  (can-meet ?recipient ?sender))
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
                                                                 

   (:method 
		(transform ?agent ?info) ;name
		() 
		((!na))
	)

   (:method 
		(transform ?agent ?info) ;name
		((has ?agent ?info ?somemedium printed)) 
		((!scan ?agent ?info))
		((has ?agent ?info ?somemedium handwritten)) 
		((!type-up ?agent ?info))
		((has ?agent ?info usb ?someformat)) 
		((!copy-to-pc ?agent ?info))
    )


   (:operator 
		(!scan ?agent ?info) 
		(	(has ?agent ?info ?somemedium paper)
		)
		()
		( 	(has ?agent ?info local-drive digital-file)
		)
	)

   (:operator 
		(!type-up ?agent ?info) 
		(	(has ?agent ?info ?somemedium paper)
		)
		()
		( 	(has ?agent ?info local-drive digital-file)
		)
	)

   (:operator 
		(!copy-to-pc ?agent ?info) 
		(	(has ?agent ?info usb ?format)
		)
		()
		( 	(has ?agent ?info local-drive ?format)
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
	;		(c) the sender has encryption software
	(:method 
		(encrypt-information ?sender ?recipient ?info) ;name
		(	(has ?sender ?info digital-file)
			(has ?sender (key ?sender ?recipient shared) digital-file) 
			;(has ?sender encryption-software)
		) 
		((!symmetric-encrypt ?sender ?recipient ?info (key ?sender ?recipient shared)))
	)

	; Encrypt unsigned information 
	;	Preconditions:
	;		(o) Placed in method
	; Effects:
	;		(a) the user has the info now encrypted info with the shared key 
	;		(a) the information now fits email and web exchange
	(:operator 
		(!symmetric-encrypt ?sender ?recipient ?info ?key) 
		() 
		() 
		(	(has ?sender (encrypted ?info (key ?sender ?recipient shared)) local-drive digital-file)
		)
		5
	)
  
	; How to symmetrically decrypt unsigned information 
	;	Preconditions:
	;		(a) the recipient has the encrypted information in digital format
	;		(b) the recipient has the shared key with the sender in digital format
	;		(c) the sender has encryption software
	(:method 
		(decrypt-information ?sender ?recipient ?info) ;name
		(
			(has ?recipient (encrypted ?info (key ?sender ?recipient shared)) digital-file) 
			(has ?recipient (key ?sender ?recipient shared) digital-file)
			;(has ?recipient encryption-software)
		)
		((!symmetric-decrypt ?recipient ?sender ?info))
	  )

	  ; Symmetrically decrypt unsigned information 
	  ;	Preconditions:
	  ;		(o) Addressed in the method
	  ; Effects:
	  ;		(a) the recipient now has the info
	  ;		(b) the info is not at the recipients local drive
  	 (:operator 
		(!symmetric-decrypt ?recipient ?sender ?info) 
		() 
		() 
		((has ?recipient ?info local-drive digital-file))
		5
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
	;		(c) the sender has encryption software
	(:method 
		(encrypt-information ?sender ?recipient ?info) ;name
		(	(has ?sender (signed ?info (key ?agent private)) digital-file)
			(has ?sender (key ?sender ?recipient shared) digital-file) 
			;(has ?sender encryption-software)
		) 
		((!symmetric-encrypt-signed ?sender (signed ?info (key ?agent private)) (key ?sender ?recipient shared)))
	)

	; Encrypt signed information 
	;	Preconditions:
	;		(o) Placed in method
	; Effects:
	;		(a) the user has the info now encrypted info with the shared key 
	;		(a) the information now fits email and web exchange
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
	;		(c) the sender has encryption software
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
	;		(a) the recipient has the encrypted and signed information
	;		(b) the recipient has the shared key with the sender
	;		(c) the sender has encryption software	  
	; Effects:
	;		(a) the recipient now has the signed info
	;		(b) the info is now at the recipients local drive
	(:operator 
	(!symmetric-decrypt-signed ?recipient ?sender ?info) 
		(	(has ?recipient (encrypted (signed ?info (key ?agent private)) 
													(key ?encryptor ?recipient shared)) digital-file)
			(has ?recipient (key ?encryptor ?recipient shared) digital-file)
		) 
		() 
		(	(has ?recipient (signed ?info (key ?agent private)) local-drive digital-file) 
		)
		5
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
;		(a) the sender has the information
;		(b) the sender has the public key of the recipient
;		(c) the sender has encryption software
	(:method 
		(encrypt-information ?sender ?recipient ?info) ;name
		(has ?sender (key ?recipient public)) 
		(has ?sender ?info digital-file)
		(has ?sender encryption-software)
	)
    (	(!asymmetric-encrypt ?sender ?recipient ?info (key ?recipient public)))
	)

	; How to encrypt-information 
	;	Preconditions:
	;		(a) the sender has the information
	;		(b) the sender has the pulic key fo the recipient
	;		(c) the sender has encryption software
	; Effects:
	;		(a) the user has the info now encrypted info with the recipients public key 
	;		(b) the information now fits readable long
	(:operator 
		(!asymmetric-encrypt ?sender ?recipient ?info ?key) 
		() 
		() 
		(	(has ?sender (encrypted ?info (key ?recipient public)) local-drive digital-file)
		)
		5
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
    ((!asymmetric-encrypt-signed	?sender 
									?recipient 
									(signed ?info (key ?agent private)) 
									(key ?recipient public)
									)
	)
    )

	 ; Asymmetricaly enrcype signed information
	 ;	Preconditions:
	 ;		(a) the sender has the public key of the recipient
	 ;		(b) the sender has the information signed by anyone's private key
	 ;	Effects:
	 ;		(a) the encrypted signed information
	 (:operator 
		(!asymmetric-encrypt-signed ?sender ?recipient ?info ?key) 
		() 
		() 
		((has ?sender (encrypted ?info ?key) local-drive digital-file)
		 )
		 5
	  )


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
                                                 

	; If the information is already available decrypted then no need to decrypt it
	(:method 
		(decrypt-information ?sender ?recipient ?info) ;name
		((has ?recipient ?info))
		((!na)) ; don't do anything
	)

  	; If the information is already available signed
    (:method 
      (decrypt-information ?sender ?recipient ?info) ;name
      ((has ?recipient (signed ?info (key ?agent private))))
      ((!na)) ; don't do anything
    )

    ; How to asymmetrically decrypt unsigned information 
	;	Preconditions:
	;		(a) the recipient has the encrypted information with own public key
	;		(b) the recipient has the private key
	;		(c) the sender has encryption software
    (:method 
    (decrypt-information ?sender ?recipient ?info) ;name
    (
		(has ?recipient (encrypted ?info (key ?recipient public)))  
		(has ?recipient (key ?recipient private))
	)
    ((!asymmetric-decrypt ?sender ?recipient (encrypted ?info (key ?recipient public))))
    )

	  ; Asymmetrically decrypt unsigned information 
	  ;	Preconditions:
	  ;		(a) the recipient has the encrypted information with their own public key
	  ;		(b) the recipient has the private key
	  ;		(c) the sender has encryption software	  
	  ; Effects:
	  ;		(a) the recipient now has the signed info
	  ;		(b) the info is now at the recipients local drive
	 (:operator 
		(!asymmetric-decrypt ?sender ?recipient (encrypted ?info (key ?recipient public))) 
		(	(has ?recipient (encrypted ?info (key ?recipient public)))  
			(has ?recipient (key ?recipient private))
		)
		() 
		(	(has ?recipient ?info local-drive digital-file)
		)
		5
	  )


    ; How to asymmetrically decrypt signed information 
	;	Preconditions:
	;		(a) the recipient has the encrypted information with own public key
	;		(b) the recipient has the private key
	;		(c) the sender has encryption software
    (:method 
    (decrypt-information ?sender ?recipient ?info) ;name
	(
		(has ?recipient (encrypted  (signed ?info (key ?agent private)) 
									(key ?recipient public)))
	)
    ((!asymmetric-decrypt-signed ?sender ?recipient (signed ?info (key ?agent private))))
    )


	  ; Asymmetrically decrypt signed information 
	  ;	Preconditions:
	  ;		(a) the recipient has the encrypted information with their own public key
	  ;		(b) the recipient has the private key
	  ;		(c) the sender has encryption software	  
	  ; Effects:
	  ;		(a) the recipient now has the signed info
	  ;		(b) the info is now at the recipients local drive
	 (:operator 
		(!asymmetric-decrypt-signed ?sender ?recipient (signed ?info (key ?agent private))) 
		(	(has ?recipient (key ?recipient private))
		)
		()
		(	(has ?recipient (signed ?info (key ?agent private)) local-drive digital-file) 
		)
		5
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
  
	; How to asymmetrically decrypt signed information 
	;	Preconditions:
	;		(a) the signer has a private key
	;		(b) the signer has the information
	(:method 
		(sign-information ?signer ?info) ;name
		(	(has ?signer (key ?signer private) digital-file) 
			(has ?signer ?info digital-file)
		)
		((!asymmetric-sign ?signer ?info (key ?signer private)))
	)


	 ; Asymmetrically sign information 
	 ;	Preconditions:
	 ;		(a) the (private) key
	 ; 		(b) the information 
	 ; Effects:
	 ;		(a) the recipient now "has" the signed info /
	 (:operator 
		(!asymmetric-sign ?signer ?info ?key) 
		()
		() 
		(
			(has ?signer (signed ?info (key ?signer private)) local-drive digital-file)
		)
		 
	  )

    ; you can always skip signing
	(:method 
		(sign-information ?sender ?info) ;name
		()
		((!na)) ; don't do anything
	)


;#     #                                                              
; #     # ###### #####  # ###### #  ####    ##   ##### #  ####  #    # 
; #     # #      #    # # #      # #    #  #  #    #   # #    # ##   # 
; #     # #####  #    # # #####  # #      #    #   #   # #    # # #  # 
;  #   #  #      #####  # #      # #      ######   #   # #    # #  # # 
;   # #   #      #   #  # #      # #    # #    #   #   # #    # #   ## 
;    #    ###### #    # # #      #  ####  #    #   #   #  ####  #    # 

	(:method 
		(verify-information ?recipient ?signer ?info) ;name
		(	(has ?recipient (key ?signer public) digital-file) 
			(has ?recipient (signed ?info (key ?signer private)) digital-file)
		)
		((!asymmetric-verify ?recipient ?signer (signed ?info (key ?signer private)) (key ?signer public)))
	)

	; Asymmetrically sign information 
	;	Preconditions:
	;		(a) see above.
	; Effects:
	;		(a) the recipient has authenticated the information wrt. signer
	;		(b) the signer cannot repudiate the information to the recipient
	(:operator 
		(!asymmetric-verify ?recipient ?signer (signed ?info (key ?signer private)) (key ?signer public)) 
		()
		() 
		(	(authenticated ?recipient ?signer ?info)
			(cannot-repudiate ?signer ?info ?recipient))
		5
	)

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
                                                   
  

	(:method 
		(set-up-2 ?sender ?recipient) ;name
		()
		((manage-keys ?sender ?recipient)
		)
    )

	; How to manage keys between sender and recipient
	; Create and share asymmetric keys from sender to recient
	; (:method 
		; (manage-keys ?sender ?recipient) ;name
		; ()
		; (	(create-and-share-asymmetric-keys ?sender ?recipient)
		; )
    ; )

	; How to manage keys between sender and recipient
	; Create and share asymmetric keys from sender to recient 
	; (:method 
		; (manage-keys ?sender ?recipient) ;name
		; ()
		; (	(create-and-share-asymmetric-keys ?recipient ?sender)
		; )
    ; )

	; How to manage keys between sender and recipient:
	; Create and share asymmetric keys from recipient to sender and vice versa
	(:method 
		(manage-keys ?sender ?recipient) ;name
		()
		(	(create-and-share-asymmetric-keys ?sender ?recipient)
			(create-and-share-asymmetric-keys ?recipient ?sender)
			(create-and-share-symmetric-keys ?sender ?recipient)
		)
    )


	; How to manage keys between sender and recipient:
	; Create and share symmetric keys between recipient and sender
	; (:method 
		; (manage-keys ?sender ?recipient) ;name
		; ()
		; (	(create-and-share-symmetric-keys ?sender ?recipient)
		; )
	; )

	; How to manage keys between sender and recipient:
	; OR do nothing
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
    
	(:operator 
		(!install-encryption-software ?user) 
		()
		() 
		((has ?user encryption-software))
		50
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
   ; 	(a) Install enrcyption software to both sender and 
   ;	(b) ...recipient
   ;	(c) Generate the key
   ;	(d) Share the key
	(:method 
		(create-and-share-symmetric-keys ?sender ?recipient) ;name
		()
		(	(install-encryption-software ?sender) 
			(install-encryption-software ?recipient) 
			(!generate-symmetric-key ?sender ?recipient)
			(share-key ?sender ?recipient))
    )

	; How to create and share symmetric keys
	; Operations:
    ; 	Do nothing - not needed.
	(:method   
		(create-and-share-symmetric-keys ?sender ?recipient) ;name
		()
		((!no-need-for-keys))
    )
  
	; How to create and share symmetric keys
	; Precondition:
	;	(a) Has encryption software
	; Operations:
	; 	(a) The user has the shared key 
	;	(b) anything fits the key
	(:operator 
		(!generate-symmetric-key ?user1 ?user2) 
		(	;(has ?user1 encryption-software)
		)
		() 
		(	(has ?user1 (key ?user1 ?user2 shared) local-drive digital-file)
			(is (key ?user1 ?user2 shared) dictatable)
		)
		5
	)


   ; How to share a shared key 
   ; Precondition:
   ;	(a) The sender has the key
   ; Operations:
   ;	(a) The sender may need to transform the key
   ; 	(b) The sender sends the key
   
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


   ; How to create and share symmetric keys
   ; Operations:
   ; 	(a) Install enrcyption software to both sender and 
   ;	(b) ...recipient
   ;	(c) Generate the keys
   ;	(d) Share the keys
	(:method 
		(create-and-share-asymmetric-keys ?sender ?recipient) ;For encryption
		()
		(	(install-encryption-software ?sender) 
			(install-encryption-software ?recipient) 
			(generate-asymmetric-keys ?sender)
			(share-public-key ?sender ?recipient)
		)
    )

	(:method   
		(create-and-share-asymmetric-keys ?sender ?recipient) ;name
		()
		((!no-need-for-keys))
	)

	(:method   
		(generate-asymmetric-keys ?user) ;name
		()
		((!no-need-for-keys))
    )

	(:method   
		(generate-asymmetric-keys ?user) ;name
		(	(has ?user (key ?user public)) 
			(has ?user (key ?user private)) 
		)
		((!na))
    )
	

	(:method   
		(generate-asymmetric-keys ?user) ;name
		()
		((!generate-asymmetric-keys ?user))
    )

	(:operator 
		(!generate-asymmetric-keys ?user) 
		((has ?user encryption-software)) 
		() 
		(	(has ?user (key ?user public) local-drive digital-file)
			(has ?user (key ?user private) local-drive digital-file) 
		)
		500
	)
  
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
 	

	(:method 
       (security-en ?sender ?recipient ?info) ;name
       ()
       (
	    (sign-information ?sender ?info)
	    (encrypt-information ?sender ?recipient ?info)
	   )
    )

	(:method 
       (security-en ?sender ?recipient ?info) ;name
       ()
       (
	    (encrypt-information ?sender ?recipient ?info)
	   )
    )

	(:method 
       (security-en ?sender ?recipient ?info) ;name
       ()
       (
	    (sign-information ?sender ?info)
	   )
    )

	(:method 
       (security-de ?sender ?recipient ?info) ;name
       ()
       (
		(decrypt-information ?sender ?recipient ?info)
		(verify-information ?recipient ?sender ?info)
	   )
    )

	(:method 
       (security-de ?sender ?recipient ?info) ;name
       ()
       (
		(decrypt-information ?sender ?recipient ?info)
	   )
    )


	(:method 
       (security-de ?sender ?recipient ?info) ;name
       ()
       (
		(verify-information ?recipient ?sender ?info)
	   )
    )
	
	
	;MAIN ***********************
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
	
	
	
; DO NOT ERASE!	
   ; (:method 
      ; (transmit-information ?sender ?recipient ?info) ;name
      ; ()
      ; (:ordered
	    ; (sign-information ?sender ?info)
	    ; (encrypt-information ?sender ?recipient ?info)
	    ; (send-info ?sender ?recipient ?info)
		; (decrypt-information ?sender ?recipient ?info)
		; (verify-information ?recipient ?sender ?info)
		; )
  ; )
 

;    #                                        #######                             
;   # #   ##### #####   ##    ####  #    #       #    #####  ###### ######  ####  
;  #   #    #     #    #  #  #    # #   #        #    #    # #      #      #      
; #     #   #     #   #    # #      ####         #    #    # #####  #####   ####  
; #######   #     #   ###### #      #  #         #    #####  #      #           # 
; #     #   #     #   #    # #    # #   #        #    #   #  #      #      #    # 
; #     #   #     #   #    #  ####  #    #       #    #    # ###### ######  ####  


; Attack Axiom
(:- (intercept-successful ?sender ?recipient ?info)	
			(shared-publicly ?info)
			(shared-publicly (key ?sender private))
			(shared-publicly (key ?sender ?recipient shared))
			(and (is-compromised network) 
				 (pass-through-data-network ?info)) 
			(and (is-compromised network) 
				 (pass-through-data-network (signed ?info (key ?any1 ?any2)))) 
			(and (is-compromised network) 
				 (pass-through-data-network (key ?anyone private))) 
			(and (is-compromised network) 
				 (pass-through-data-network (key ?anyone ?anyoneelse shared)))
			(and (is-compromised ?recipient ?location) 
				 (has ?recipient ?info ?location ?someformat))
			(and (is-compromised ?recipient ?location) 
				 (has ?recipient (key ?anyone private) ?location ?someformat))
			(and (is-compromised ?recipient ?location) 
				 (has ?recipient (key ?anyone ?anyoneelse shared) ?location ?someformat))
			(and (or (is-bugged ?sender) (is-bugged ?recipient)) 
					 (shared-by-phone ?sender ?recipient ?info))
			(and (or (is-bugged ?sender) (is-bugged ?recipient)) 
					 (shared-by-phone ?sender ?recipient (key ?anyone private)))
			(and (or (is-bugged ?sender) (is-bugged ?recipient)) 
					 (shared-by-phone ?sender ?recipient (key ?anyone ?anyoneelse shared)))
			(and (or (is-followed ?sender) (is-followed ?recipient)) 
					 (shared-in-person-orally ?sender ?recipient ?info))
			(and (or (is-followed ?sender) (is-followed ?recipient)) 
					 (shared-in-person-orally ?sender ?recipient (key ?anyone private)))
			(and (or (is-followed ?sender) (is-followed ?recipient)) 
					 (shared-in-person-orally ?sender ?recipient (key ?anyone ?anyoneelse shared)))
			(and (is-compromised cloud-access ?sender)
				 (has ?sender ?info shared-drive ?someformat))
			(and (is-compromised cloud-access ?sender) 
				 (has ?sender (key ?anyone ?anyoneelse shared) shared-drive ?someformat))
			(and (is-compromised cloud-access ?sender)
				 (has ?sender (key ?anyone private) shared-drive ?someformat))
			(and (is-compromised cloud-access ?recipient)
				 (has ?recipient (link-to ?info)))
			(and (is-compromised cloud-access ?recipient) 
			     (has ?recipient (link-to (key ?anyone ?anyoneelse shared))))
			(and (is-compromised cloud-access ?recipient) 
				 (has ?recipient (link-to (key ?anyone private))))
)


 
 (:- (tampering-successful ?holder ?info)	
									(shared-publicly (key ?sender private))
									(shared-publicly (key ?sender ?anyoneelse shared))
									(and (is-compromised network) (pass-through-data-network ?info)) 
									(and (is-compromised network) (pass-through-data-network (key ?anyone private))) 
									(and (is-compromised network) (pass-through-data-network (key ?anyone ?anyoneelse shared)))
									(and (is-compromised ?holder ?something) (is-at ?holder ?something ?info))
									(and (is-compromised ?holder ?something) (is-at ?holder ?something (key ?anyone private)))
									(and (is-compromised ?holder ?something) (is-at ?holder ?something (key ?anyone ?anyoneelse shared)))
									(and	(is-compromised cloud-access ?holder)
											(is-at ?holder shared-drive ?info)
									)
									(and	(is-compromised cloud-access ?holder) 
											(is-at ?holder shared-drive (key ?anyone  ?anyoneelse  shared))
									)
									(and	(is-compromised cloud-access ?holder)
											(is-at ?holder shared-drive (key ?anyone private))
									)
								
)




; ######                                         
 ; #     #  ####  #    #   ##   # #    #          
 ; #     # #    # ##  ##  #  #  # ##   #          
 ; #     # #    # # ## # #    # # # #  #          
 ; #     # #    # #    # ###### # #  # #          
 ; #     # #    # #    # #    # # #   ##          
 ; ######   ####  #    # #    # # #    #          
                                                
  ; #####                                         
 ; #     # #####  ######  ####  # ###### #  ####  
 ; #       #    # #      #    # # #      # #    # 
  ; #####  #    # #####  #      # #####  # #      
       ; # #####  #      #      # #      # #      
 ; #     # #      #      #    # # #      # #    # 
  ; #####  #      ######  ####  # #      #  ####  











    (:method 
    (accomplishment1) ;name
	(
	   ; Requirements Section
	   (can-read patient proof-of-visit)
	  
	   ; Security Section
	   (authenticated patient doctor proof-of-visit)
	   (not (intercept-successful doctor patient proof-of-visit))
	)
    ((!done))
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
	;Domain Assumptions
	(has doctor proof-of-visit local-drive digital-file)
	;(is proof-of-visit dictatable)

	(allow email)
	;(allow sms)
	;(allow in-person)
	;(allow phonecall)

	(has doctor patient email-address)
	(has patient doctor email-address)
	(has doctor patient phone-number)
	(has patient doctor phone-number)
	(can-meet doctor patient)
   
	;Vulnerability Assumptions
	;(is-compromised patient local-drive)
	;(is-bugged doctor)
	;(is-compromised patient physical)
	;(is-followed chair)
	(is-compromised network)
	(is-compromised patient phone)
  ) 
 (:ordered
	(set-up-2 doctor patient)
	(transmit-information doctor patient proof-of-visit)
	(accomplishment1)
  )
  )

(find-plans 'problem1 :verbose :plans :optimize-cost t)
```
