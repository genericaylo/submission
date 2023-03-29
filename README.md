# Overview
The following is the HTN SHOP2 sample specification accompanying our RE@Next! 2023 submission *"Towards automating security requirements implementation using secure workflow patterns"*. [The listing](https://github.com/genericaylo/submission/blob/main/src/RE2023.lisp) can be downloaded as a LISP file from the repository. It contains: (a) workflow patterns for securely transmitting information between two actors using various communication channels and utilizing cryptographic primitives, (b) example attack trees for confidentiality, authentication and integrity. In later sections, we use these assets to reason with various security requirements and vulnerability assumptions. 

The presented formalization here is much more complex and uses different conventions than the ones in the paper (e.g. second order LISP-like terms are extensively used), without, however, departing from the main ideas and vision in the paper. The formalization can be seen as one of the many possible that can be devised for solving the same problem domain (securely transferring documents between two parties) and is given as an example of what is possible rather than an authoritative model for the domain. The formalization of choice is a result of balancing between expressiveness, exact reasoning needs (e.g. do we need to reason about many different channels?), and computational efficiency and requires substantial validation effort with domain experts. These tasks are central for our future research agenda.

[The listing](https://github.com/genericaylo/submission/blob/main/src/RE2023.lisp) can be compiled and used as-is by the SHOP2 planner. Installation instructions are provided below.


# The Model

## Key aspects
The specification focusses on the exchange of information between two parties making certain assumptions on the devices and media in which the information is stored, and the computational devices that the participants use. The possibilities are by no means meant to be exhaustive but rather to provide an illustration of the modeling and reasoning possibilities available through out framework. 

Note that the entire domain specification, except for the attack tree axioms and the final method, is really an HTN description of an large and complex AND/OR goal decomposition, where methods are used to implement intermediate AND and OR decomposed nodes. Thus, the entire specification can be visualized using iStar 2.0 constructs. 

## Computational Devices
Participants in the workflows are assumed to have access to the following devices:
* A PC or other computer connected to the internet. The PC is the only devices where cryptographic functions can be executed.
* A mobile phone, capable of sending text messages with file attachments. Actors can connect their phone to their PC to exchange files. 
* A printer and a scanner (with no handwriting recognition). 
* USB drives or other portable digital storage medium

## Formats and Media

Information is at any point in time available with an actor. A special predicate is used to signify this:
```lisp
(has ?agent ?info ?medium ?format)
```
While ``` ?agent ``` and ```?info``` can be anything, ```?medium``` and ```?format``` are restricted as follows:

Possibilities for medium:
* Local-drive: meaning the hard-drive of the PC
* shared-folder: implies that the file exists also in the cloud and accessible for anyone with access to the cloud account. (unused)
* mailbox: the inbox or outbox of an agent’s email account, which is assumed to reside both on a server and as a local copy.
* phone: any part of the agent’s smartphone (e.g. text messages, file-system or email app), such that hacking the phone implies full access to that location.
* USB: shorthand for any portable digital storage device, including e.g. CDs, DVDs or other media.
* Physical: any physical location in which an agent has access: e.g., their pocket or their desk. 

Possibilities for format:
* digital-file
* paper which can be either printed (thus, OCR-able) or handwritten.

Information can be scanned, typed-up and copied from one machine to another. Printing information is omitted for simplicity; anything digitally available can be assumed to printed as well. We generally assume that users and/or the technology they use will perform actions that inadvertently expand the attack surface by copying the information from one medium to the other. For example the following assumptions:
* Information in shared-drive will eventually sync to the local-drive.
* Information in the e-mailbox (e.g. an attachment), will be downloaded to local-drive.
.. mean that compromising a user's PC, automatically means that information in their server-side mailboxes and shared drive is also vulnerable through user syncronization actions or, e.g., login monitoring and credentials theft.

## Transferring information
Information can be transferred in any of the following ways:
* Email.
* SMS, i.e., text messaging, which is assumed to also support attachments.
* Phone-call oral exchange, whereby one actor is calling another and offers the information verbally. The other actor is assumed to jot down the information manually in their physical space. 
* In person exchange, whereby one actor visits the physical space of another actor and delivers the information in paper or digital format (e.g. USB key).
* In person oral exchange, like phone-call oral exchange but requiring a visit to another persons space.

## Encryption and Decryption Methods

Encryption can be _symmetric_ or _asymmetric_. In the former case the participants exchange a shared key and use their document viewer or word processor to protect/encrypt the document with the key. As such no extra software is required. However, the shared key needs to be exchanged securely. 

For asymmetric encryption public/private key pairs need to be generated and the public parts exchanged in a way that is not necessarily secured. We however assume that the standard versions of document viewers and processors do not trivially support public key cryptography. As such, specialized software needs to be installed for such, such as for example [OpenPGP](https://www.openpgp.org/).

## Digital Signatures
Digital signing is generally asymmetric through the use of third-party software such as [OpenPGP](https://www.openpgp.org/). It is further assumed that signing and encryption take place independently and in this order when both are needed. Uncompromised signing guarantees authentication, protection against tampering and non-repudiation.

The model does not support message authentication codes (MAC) which is the symmetric counterpart of digital signing but with limited guarantees.

## Key management
Key management is a step that generally precedes encryption and/or signing, and involves key generation and sharing. The sharing of keys follows the same methods as the sharing of any other information. However, advanced key establishment protocols (e.g. Diffie-Hellman) that may need specialized software or synchronous communication are not currently included as methods, due to being unrelated to the context and examples of use we are considering here. Thus, shared key exchange, which is sensitive information, must take place using a channel that is assumed to be secure (e.g. in person exchange, a phone call or other method) depending on the *vulnerability assumptions* in effect. 

## Attack Trees
Attack trees are simple axioms connecting a high-level characterization of the attack (the negation of a security requirement) with a logical formula describing conditions under which the attack is accomplished, hence the security requirement successfully breached. Notice that the components of the formula appear in any of: effects and preconditions of operations and/or methods, vulnerability assumptions or domain assumptions. The following attack trees are introduced:

* **Con** ``` (ConBreached ?sender ?recipient ?info) <= ...``` followed by various combinations of effects and assumptions that make such breach possible. The predicate means that a piece of ```?info``` transmitted from ```?sender``` to ```?receiver``` was read by an unauthorized third party.
* **Int** ``` (IntBreached ?sender ?recipient ?info) <= ...``` followed by various combinations of effects and assumptions that make such breach possible. The predicate means that a piece of ```?info``` transmitted from ```?sender``` to ```?receiver``` was altered by an unauthorized third party.
* **Auth** ``` (AuthSuccessful ?sender ?recipient ?info) <= (and (authenticated ?recipient ?sender ?info) (not (IntBreached ?sender ?recipient ?info) ))``` meaning that authentication is successful for ```?info``` being transmitted from ```?sender``` to ```?recipient```, if the ```?recipient``` was able to authenticate that the ```?info``` was indeed of the ```?recipient``` and that any tampering related to this exchange was not possible (e.g. no private key reached a compromised location, invalidating a signature).
* **NonRep** ``` (Repudiate ?agent ?info) <= (not (AuthSuccessful ?agent ?recipient ?info))``` meaning that ```?agent``` can repudiate that  ```?info``` never originated by them if in the solution there is no ```?recipient``` that successfully authenticates ```?info```.

A few remarks here:
* The attack tree "heads" (the LHS of the implications) describe a breach within the context of a transmission of information from a sender to a receiver, since different requirements may be posed for different such instances.
* The heads are not necessarily negative, such as the authentication one that is used without negation.
* The axioms are work in progress and subject to revisions during this exploratory phase. For example, a more accurate axiom for NonRep could be technology-specific: that the agent has actually signed the information in an uncompromised fashion and has shared the document and signature with an independent agent that can serve as judge. This would however require some additions to the constructions.
* Additional axioms may be needed for various security or privacy requirements and complex formulations thereof including non-disclosure, redundancy, retention or disposal etc.

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

Alternativelly we can define a domain specific method:
```lisp
    (:method 
	(sendInvoice ?sender ?recipient) ;name
	() ; precondition
	(:ordered
		(manage-keys ?sender ?recipient)
		(transmit-information ?sender ?recipient invoice)
		(final)
	)
    )
```

... and have the main method use that instead:

```lisp
	; ... initial state above
	(:ordered
		(sendInvoice supplier contractor)
	)
```

# Relationship to Goal Models

The image below shows how the various visual elements developed in STS-ml are translated into the various chunks of the HTN specs. The actual transmission of the invoice (a domain specific requirement) is translated into the generic method ```transmit-document ...``` taken from the community-maintained repository. The security requirements, appearing as decorations at the bottom of the document shape (the large rectangle) are translated into preconditions of the ```final``` action after possibly being formulated as negated heads of attack trees. 


<img src="https://github.com/genericaylo/submission/blob/main/img/translation.png?raw=true" alt="Description of relationship between goal diagrams and resulting HTN spec chunks" width="450"/>

# Running 
To identify plans, SHOP2 requires running 
```lisp
(find-plans 'problem1 :verbose :plans :optimize-cost t)
```

Please see below for rough installation instructions.

## Running Example

Let us now explore the example of the interaction between the supplier and the contractor as seen in the paper. As stated above, the example here is much more elaborate than the one that has been presented in the paper, which was simplified due to space constraints.

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

When looking at the plan we discard all the ``` (!NA) ``` actions, which simply signify optional actions (e.g. key creation and exchange, encryption, etc.) that were not chosen. What remains is a simple email action of the invoice from the supplier to the contractor, without any security steps. Notice also the CPU time and inferences it takes to generate the plan, to compare with the examples that follow.


### Case 2 – Invoice confidential.

Let us now assume that we specify a confidentiality requirement: the contractor wants to be able to ensure that has not been read by unauthorized parties. We state this requirement through a negated attack:

```lisp
		; ++++++++++++++++++++++++++++++++++++++++++++++
		; + S E C U R I T Y    R E Q U I R E M E N T S +
		; ++++++++++++++++++++++++++++++++++++++++++++++

		(not (ConBreached supplier contractor invoice))
```

However, we do not add any vulnerability assumptions. The planner will return the exact same plan:

```text
Defining problem PROBLEM1 ...
---------------------------------------------------------------------------
Problem #<SHOP3::PROBLEM PROBLEM1> with :WHICH = :FIRST, :VERBOSE = :PLANS, OPTIMIZE-COST = T

Totals: Plans Mincost Maxcost Expansions Inferences  CPU time  Real time
           1  -178.0  -178.0        374       6911     0.109      0.109

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
           1   265.0   265.0      35123     841859     9.938      9.922

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

		(AuthSuccessful supplier contractor invoice)
```

The plan that will return now is different:

```text
Defining problem PROBLEM1 ...
---------------------------------------------------------------------------
Problem #<SHOP3::PROBLEM PROBLEM1> with :WHICH = :FIRST, :VERBOSE = :PLANS, OPTIMIZE-COST = T

Totals: Plans Mincost Maxcost Expansions Inferences  CPU time  Real time
           1  2544.0  2544.0      14853     334461     3.953      3.968

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

		(not (ConBreached supplier contractor invoice))
		(AuthSuccessful supplier contractor invoice)
```

Then we will get the following plan:

```text
Defining problem PROBLEM1 ...
---------------------------------------------------------------------------
Problem #<SHOP3::PROBLEM PROBLEM1> with :WHICH = :FIRST, :VERBOSE = :PLANS, OPTIMIZE-COST = T

Totals: Plans Mincost Maxcost Expansions Inferences  CPU time  Real time
           1  2788.0  2788.0      38166     920896    10.422     10.418

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
           1  3526.0  3526.0     215114    5343986    63.703     63.709

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

* Install a Common Lisp in your system. We have tried it with [Steel Bank Common Lisp](http://www.sbcl.org/). The [SHOP3 pages](https://github.com/shop-planner/shop3) offer additional recommendations.
* Install SHOP3 following directions [in their github page](https://github.com/shop-planner/shop3). We used the quicklisp installation option solution on windows successfully.
* Save [the listing](https://github.com/genericaylo/submission/blob/main/src/RE2023.lisp) in a .lisp file, such as ``` Example.lisp```
* Once in sbcl and SHOP3 is loaded (e.g. through ```(load "~/init.lisp")```, run ```(load "Example.lisp")```
* You can make changes to the .lisp file and reload as above; definitions will be replaced.
