```
|=----------------------------------------------------------------------------=|
|=--------=[ FixIT-Scool is an application for schools and students ]=--------=|
|=----------------------------------------------------------------------------=|
|=-------------------=[ lol1074 but for you BitCrucio  ]=---------------------=|
|=----------------------------------------------------------------------------=|
|=----------------------------=[ FixIT-School ]=------------------------------=|
```
---                                                                          ---

```
--=[ Table of Contents:

    0.0 - warnings
    1.0 - introduction
    1.1 - install
       1.2 - use
       1.3 - config
       1.4 - data struct  
    2.0 - security
       2.1 - how to control access
          2.1.1 advanced information 
       2.2 - whitelist IP
          2.2.1 advanced whitelist
             2.2.2 udp payload flowchart explained
    3.0 - contributors
      3.1 - rules
    4.0 - license
      4.1 - AI not admitted
    5.0 - Doc for code 
    6.0 - Creator and other

```
---                                                                     ---

```
--=[ 0.0 [ warnings ]
            
                 


                  < Users >  So, is the UDP pipe stable?
                                             time 10.50 

                                                                   < Dev > Well, the header decryption is working,
                                                                           but the whitelist logic, is currently held together by hope and caffeine.
                                                                                                                                         time 10.55
                  < Users > Is it production ready?
                                        time 10.56
                                                                   < Dev > ¯\(°_o)/¯
                                                                           time 10.57

                 
                 This little gag was created to make it clear that the project is not finished and that it is currently not usable in a real context.
                 We will continue to plan it, but it will take time and a lot of madness.

                 --=[ IMPORTANT
                      Having said that, for the sake of transparency,
                      I would also like to point out that all the material in this repository is made by me,
                      except for some things in the README.md, which are:
 
                             -_-_-_ the ascii art present in section number < 4.0 > in this case the piece of paper \
                                    You can get it from this link. I recommend it to you if you want to get the same one as me or go deeper to find others. \

                                    --- [ > URL => < https://asciiart.website/art/1051 > -_-_-_

                             -_-_-_ Another site from which I got techniques and, above all, the style I then shaped to make it my own is phrack. \
                                    I recommend it, especially if you're passionate about computer security. phrack is an annual magazine. \

                                    --- [ > URL => < https://phrack.org/ > -_-_-_


                                                                    
--=[ 1.0: [ Introduction ]


                          who wants a school with dilapidated and badly functioning PCs? :)


         FixIT-Scool solves this very problem, in fact it acts as a decentralized system to support,
         technicians and assistants in promptly identifying and resolving computer problems.
         within the school perimeter.



--=[ 1.1: [ Install ]


        To install FixIT-Scool you just need to clone the following repository,
        with the subsequent access to the destination folder you selected.
        If you haven't done so, the default folder will be present.


       --=[ ATTENTION

             I wasted 2 minutes of my existence explaining how to clone the repo for neophytes or those who simply forgot the commands.
             Now, don't come telling me this repository isn't inclusive. Here are the steps

              --- [ > Repo to clone for source code, Link (non-clickable purely for aesthetic, deal with it) < https://github.com/lol1074/FixIT-School.git >
              --- [ > command for installation < git clone --recursive https://github.com/lol1074/FixIT-School.git >
              --- [ > enter the folder  < FixIT-School >


   --=[ 1.2: [ Use ]


              To use FixIT-Scool you will first need to clone the repo, as explained in section 1.1.
              After doing this you will be able to enter the destination folder and then compile the go packages.


                  --- [ > enter the newly cloned folder, default name a < FixIT-School >
                  --- [ > command to compile recursively < find . -name "*.go" -exec go build {} + >

              with the following command you can recursively compile all the files,
              small note I am quite aware of the presence of the mod.go file,
              but since it is still in a very embryonic stage and with almost nothing inside I prefer this option


   --=[ 1.3: [ Config ]

           --=[ ATTENTION

                Only the most important ones are shown here. For those who want to go into more detail or want to modify something more advanced,
                you will find everything in the wiki as soon as it is ready.


            to change the settings you need to modify the source code,
            specifically the file < generateIV.go >, in this file it is used as main while the other two as placeholders to create a seed,
            which is then passed to the aforementioned file

            To implement the changes you need to open the < generateIV.go > file. You can then change the following settings.
            I'm leaving a small legend to indicate what problems altering the settings can cause.
            --=[ Legend
                 - [+] => it can be modified without any problem
                 - [/] => It can be modified but it may cause optimization and responsiveness issues.
                 - [-] => it can be modified but will inevitably lead to performance drops.

              [+] - SALT_SIZE: Cryptographic salt size in bytes (default 32).
              [/] - KEY_SIZE: Total size of the generated key (default 64).
              [/] - HMAC_KEY_SIZE: shared secret data string used to verify the authenticity of the sender and recipient (default 32).
              [-] - ENCRYPTION_KEY_SIZE: encryption key size (default 32).
              [+] - RANDOM_COMPONENT_SIZE: Size of the entropy random component (default 32).
              [-] - PBKDF2_ITERATIONS: Number of hashing iterations (default 100,000).
              [-] - SCRYPT_N: CPU/Memory cost parameter for Scrypt (default 32768).


    
   --=[ 1.4: [ Data struct ]

            The currently tested and functioning system for cryptography is also integrated to enter metadata as headers for two factors:

           1 - Security: ensure data integrity and origin via HMAC and fingerprints.
           2 - Identification: provide granular tracking of the ticket source (SchoolID) 
               and the nature of the fault (TicketType).

        ---=[ Marker Generation Flow:

         [ Entropy Data ] + [ System Components ]
                      |
                      v
              +-------+-------+-------+-------+-------+-------+-------+
              | PREF  | SEP   | TIME  | SEP   | RAND  | SEP   | UUID  |
              +-------+-------+-------+-------+-------+-------+-------+
                                  |
                                  |-----> [ Marker ID Created ]
                                  |
              +-------------------+-------------------+
              |                                       |
              v                                       v
      [ SignMarkerID ]                       [ ValidationHash ]
      (HMAC/Signature)                       (Cross-Reference)
              |                                       |
              +-------------------+-------------------+
                                  |
                                  v
                       --=[ FINAL TICKET OBJECT ]=--

     This logic ensures that every marker is unique, timestamped, and cryptographically tied to the machine that generated it.
     To access more information I will leave everything inside the wiki as previously stated



   --=[ 2.0: [ Security ]

            DISCLAIMER: In this context, we use the word "hacking" in its
                        original and noble meaning: the art of exploring, understanding,
                        and manipulating a system to see how it works.

                        Therefore, you will NOT find instructions on how to circumvent security
                        here. You will find instructions on how to master the code.
                        ...although, I might leave you a small gift or clue to
                        play video games even if you can't, for you in the future,
                        if this system ever sees the light of day. ;)
           

       --=[ 2.1: [ How to control access ]

                This section illustrates the method for verifying that the ticket is authentic and authorized for access.
                Obviously, this is only a minimal representation to implement the main security systems.

                This diagram illustrates how the system processes a TicketMarker,
                from decoding the cryptographic signature to managing the status in the < TicketRegistry >.



       --=[ Verification and Validation Flow

 
       [ INPUT ]
           |
           v
+-----------------------------+
| DecryptAndVerifySignature() | <--- Input: encodedSignature (Base64)
+--------------+--------------+
               |
               | 1. Base64 Decode
               | 2. AES-GCM Decrypt (Key: mg.encryptionKey)
               |
               v
       [ Decrypted Signature ]
               |
               |
               v
+-----------------------------+
|        VerifyMarker()       | <--- Check logical integrity
+--------------+--------------+
               |
               +---> [ CHECK 1: Version ] --------+
               |     (marker.Version == VERSION)  | [FAIL] -> error
               |                                  |
               +---> [ CHECK 2: Expiration ] -----+
               |     (time.Since > 24h)           | [FAIL] -> error
               |                                  |
               +---> [ CHECK 3: Integrity ] ------+
               |     (Hash vs expectedHash)       | [FAIL] -> error
               |                                  |
               v                                  v
        [ MARKER VALID ]                  [ REJECTED / ERROR ]
               |
               |
      _________v_______________________________________________
     |                                                         |
     |                TICKET REGISTRY (Lifecycle)              |
     |_________________________________________________________|
               |                    |                    |
               v                    v                    v
      [ RegisterMarker ]    [ ValidateMarker ]    [ RevokeMarker ]
               |                    |                    |
      +--------+--------+    +------+---------+    +------+------------------------------+
      | Generate String |    | Search ID in   |    | Set: ValidUntil = time.Now()        |
      | Random (32ch)   |    | tr.markers     |    +------------------+------------------+                                     
      +--------+--------+    +-------+--------+                       |
               |                     |                                |
      +--------+-------+    +--------+---------+                      |
      | Save Record    |    | Check Expiration |               +------+----------+
      | in tr.markers  |    | (ValidUntil)     |               | Meta:           |
      +----------------+    +------------------+               | revoked=true    |
                                                               +-----------------+


      As you can see in the flow chart, the system adopts various techniques for verification,
      but going into specifics I will show what it actually does.

          --=[ 2.1.1: [ Advanced information ]

                    --=[ NOTE
              
                             While there's more information in this area than the flowchart in the previous section <2.1>,
                             not all the details will be covered here,
                             so we ask you to visit the wiki if you'd like more information.

                             Or read the code yourself!


                    --=[ 1: Cryptographic Security
                              The DecryptAndVerifySignature() function uses AES-GCM,
                              guaranteeing not only the confidentiality but also the authenticity of the data (Authenticated Encryption).

                    --=[ 2: Exhaustive Validation
                              VerifyMarker acts as a logical firewall. It not only checks whether the ticket exists,
                              but also recalculates its hash (expectedValidationHash) using the ID, Signature, and SchoolID
                              to prevent tampering attempts.

                    --=[ 3: State Management (Registry)
                              --- [ > Immutability: Once registered, an ID cannot be reused (marker already registered).
                              --- [ > Revoke: Revoking does not delete the record but temporarily invalidates it and adds metadata for auditing (revoke_reason).


   --=[ 2.3: [ Whitelist IP ]
              --=[ TODO: I know it seems strange but I also have a social life

              In this section there is a flowchart,
              that explains how the program manages the white list system to avoid attacks on the server.
  
+--------------------------------------------------------------------------------------------------+
|                                  SYSTEM INGRESS & PRE-PROCESSING                                 |
+--------------------------------------------------------------------------------------------------+
|                                                                                                  |
|   [ Client Request ]                                                                             |
|           |                                                                                      |
|           v                                                                                      |
|   +----------------+      +------------------------------------------------------------------+   |
|   | Packet Ingress | ---> |  LOGGING SYSTEM (Audit Trail of raw entry)                       |   |
|   +-------+--------+      +------------------------------------------------------------------+   |
|           |                                                                                      |
|           v                                                                                      |
|   +-------------------------+                                                                    |
|   |  HEADER DECRYPTION      | :: (Extract Encrypted Metadata from Packet Headers)                |
|   |  LAYER (Stage 0)        |                                                                    |
|   +-------+-----------------+                                                                    |
|           |                                                                                      |
|           |  (Separate Metadata from Payload)                                                    |
|           +----------------------------+                                                         |
|           |                            |                                                         |
|           v                            v                                                         |
|   [ Payload Buffer ]           [ UDP TRANSMISSION PIPE ]  >>>>>>>>>> (Fast Lane Sidecar)         |
|   (Waiting Signal)                     |                                                         |
|           |                            |                                                         |
+-----------|----------------------------|---------------------------------------------------------+
            |                            |
            |                            v
+-----------|--------------------------------------------------------------------------------------+
|           |                  SECURITY CORE & VALIDATION ENGINE                                   |
+-----------|--------------------------------------------------------------------------------------+
|           |                            |
|           |                    +-------+-------+
|           |                    |  AUTH SYSTEM  | <--- (Recv Metadata via UDP)
|           |                    +-------+-------+
|           |                            |
|           |                    +-------v-------------------------+
|           |                    | STAGE 1: INTEGRITY CHECK        |
|           |                    | (Decrypt Secondary Header)      |
|           |                    +-------+-------------------------+
|           |                            |
|           |                    +-------v-------+       NO        +----------------------+
|           |                    | Authenticity  | --------------> |  ERROR 400 BAD REQ   |
|           |                    | Verified?     |                 |  (Invalid Signature) |
|           |                    +-------+-------+                 +-----------+----------+
|           |                            | YES                                 |
|           |                            v                                     |
|           |                    +-------------------------+                   v
|           |                    |  METADATA STORE         |            (Terminates Conn)
|           |                    |  (Cache/Context Save)   |
|           |                    +-------+-----------------+
|           |                            |
|           |                            v
|           |                    +-------+-------------------------+
|           |                    | STAGE 2: ACCESS CONTROL         |
|           |                    | (Whitelist & Policy Check)      |
|           |                    +-------+-------------------------+
|           |                            |
|           |                    +-------v-------+       NO        +----------------------+
|           |                    | Whitelisted   | --------------> |  BLOCK / DROP        |
|           |                    | Identity?     |                 |  (Security Alert)    |
|           |                    +-------+-------+                 +-----------+----------+
|           |                            | YES                                 |
|           |                            v                                     |
|           |                    +-------------------------+                   v
|           |                    |  SIGNAL: "RELEASE"      |            (Terminates Conn)
|           |                    +-----------+-------------+
|           |                                |
+-----------|--------------------------------|-----------------------------------------------------+
            | <----- (Unlock Trigger) -------+
            v
+--------------------------------------------------------------------------------------------------+
|                                   CORE ANALYTICS & EXECUTION                                     |
+--------------------------------------------------------------------------------------------------+
|                                                                                                  |
|   +-----------------------+                                                                      |
|   |  GATEKEEPER OPEN      |                                                                      |
|   |  (Re-assemble flow)   |                                                                      |
|   +-------+---------------+                                                                      |
|           |                                                                                      |
|           v                                                                                      |
|   +---------------------------------------+                                                      |
|   |  ticket security system               |                                                      |
|   |  (Business Rules / Data Processing)   |                                                      |
|   +---------------------------------------+                                                      |
|           |                                                                                      |
|           v                                                                                      |
|     _--=[ 200 OK / RESPONSE ]=--_                                                                |
|                                                                                                  |
+--------------------------------------------------------------------------------------------------+

       --- [ > The specifications that make this methodology very powerful are:

               - Data Plane: Holds the payload in a suspended state.
               - Control Plane (UDP): Asynchronously processes security headers via a dedicated pipe.
               - Zero-Trust Validation: No packet reaches the core logic without passing both the Integrity Check (Stage 1) and the Whitelist Policy (Stage 2).

               --=[ 2.2.1 [ advanced whitelist ]

                           Here the operation is explained in more detail, even in a literary way, in addition to greater accuracy.
                            
                        --=[ Ingress & Cryptographic Separation
                               Upon packet arrival, the system engages the Header Decryption Layer (Stage 0).
                               This initial pass does not inspect the full payload but focuses strictly on the packet headers.
                               Decoupling: The encrypted metadata headers are stripped from the main packet.
                               Payload Buffering: The main data payload is placed in a Suspended State (Hold Buffer). It is rendered inert and cannot trigger any backend logic.
                               UDP Sidecar Injection: The extracted metadata is securely forwarded to a dedicated high-speed UDP Validation Pipe.
                               This asynchronous channel acts as the system's "Gatekeeper."


                             --=[ The UDP Security Pipeline (Control Plane)
                                      The UDP pipe executes a rigid, multi-stage verification process. This is a "Fail-Fast" environment;
                                      any deviation results in immediate termination.

                             --=[ Stage 1: Integrity & Decryption:
                                      The system decrypts the secondary internal header. It verifies the cryptographic signature to ensure the metadata,
                                      has not been < tampered with during transit >.
                                      Failure Condition: If the signature is invalid or decryption fails, the system immediately returns a < 400 Bad Request > and severs the connection.
                                      Metadata Persistence: Validated metadata is serialized and stored in a temporary high-performance cache context.
                                      This allows for stateful analysis of a stateless UDP packet.

                             --=[ Stage 2: Access Control & Whitelisting
                                         Once integrity is guaranteed, the system transitions to logic validation using the < Identity Governance Engine >.
                                         Whitelist Verification: The extracted identity tokens are cross-referenced against a strict Whitelist Policy.
                                         Contextual Analysis:** The system checks not just < who > is sending the data, but < if > they are allowed to send it in this specific context.
                                         Failure Condition: If the identity is not whitelisted, the iteration is BLOCKED.
                                         No error is returned to the attacker to prevent enumeration; the connection is silently dropped or logged as a security alert.

                             --=[ Synchronization & Final Execution
                                  Only upon successful completion of all UDP pipeline checks does the Control Plane issue a "RELEASE" Signal.
                                  The Main Server receives this signal, unlocks the Payload Buffer, and re-associates the validated metadata with the payload.
                                  The packet is then forwarded to the < Deep Analysis Core > for final business logic processing and response generation (200 OK).


--=[ 2.2.2 [ udp payload flowchart explained ]
+---------------------------------------------------------------------------------------------------------+
|                                    UDP CONTROL PLANE: DEEP INSPECTION                                   |
+---------------------------------------------------------------------------------------------------------+
|  (Input from Ingress)                                                                                   |
|           |                                                                                             |
|           v                                                                                             |
|   +-------+-------+                                                                                     |
|   | UDP RECEIVER  | ---> [ Traffic Rate Limiter / DDoS Shield ]                                         |
|   +-------+-------+           |                                                                         |
|           |                   v (Excessive Load?)                                                       |
|           |               +---+---+                                                                     |
|           |               | DROP  |                                                                     |
|           |               +-------+                                                                     |
|           v                                                                                             |
|   +-------------------------+                                                                           |
|   | HEADER DECRYPTION CORE  |                                                                           |
|   | (Standard AES/RSA Mod)  |                                                                           |
|   +-------+-----------------+                                                                           |
|           |                                                                                             |
|           +-----------------------------------------------------+                                       |
|           | (Decryption Success?)                               | (Fail)                                |
|           v                                                     v                                       |
|   +-------+-------+                                   +---------+---------+                             |
|   | STRUCT PARSER |                                   | EXCEPTION HANDLER |                             |
|   +-------+-------+                                   +---------+---------+                             |
|           |                                                     |                                       |
|           v                                                     v                                       |
|   +-------------------------+                         [ RETURN 400 BAD REQ ]                            |
|   | STAGE 1: INTEGRITY      |                         (Invalid Ciphertext)                              |
|   | (Hash/Sig Verification) |                                                                           |
|   +-------+-----------------+                                                                           |
|           |                                                                                             |
|           +-----------+-----------------------------------------+                                       |
|           | (Match?)  |                                         | (Mismatch/Tampered)                   |
|           v           |                                         v                                       |
|   +-------------------+-----+                         +---------+---------+                             |
|   | METADATA EXTRACTION     |                         | SECURITY TRIGGER  |                             |
|   | & CONTEXT STORE         |                         | (Log Incident)    |                             |
|   +-------+-----------------+                         +---------+---------+                             |
|           |                                                     |                                       |
|           v                                                     v                                       |
|   +-------------------------+                         [ RETURN 400 BAD REQ ]                            |
|   | STAGE 2: ACCESS LOGIC   |                         (Integrity Violation)                             |
|   | (Whitelist Engine)      |                                                                           |
|   +-------+-----------------+                                                                           |
|           |                                                                                             |
|           |    +---------------------+                                                                  |
|           +--> | DB/CACHE LOOKUP     |                                                                  |
|           |    +----------+----------+                                                                  |
|           |               |                                                                             |
|           v               v                                                                             |
|   +-------+---------------+-------+                                                                     |
|   | POLICY DECISION POINT (PDP)   |                                                                     |
|   +-------+---------------+-------+                                                                     |
|           |               |                                                                             |
|           | (Allowed)     | (Denied / Not Found)                                                        |
|           |               +-------------------------------------+                                       |
|           v                                                     |                                       |
|   +-------------------------+                         +---------v---------+                             |
|   | TOKEN GENERATION        |                         | BLOCKING ROUTINE  |                             |
|   | (Create Session Key)    |                         | (Silent Drop)     |                             |
|   +-------+-----------------+                         +---------+---------+                             |
|           |                                                     |                                       |
|           v                                                     v                                       |
|   +-------+-----------------+                         [  STOP ITERATION  ]                              |
|   | INTER-PROCESS COMMS     |                         (Blacklist IP add)                                |
|   | (IPC / Signal Emitter)  |                                                                           |
|   +-------+-----------------+                                                                           |
|           |                                                                                             |
|           |  >>> SEND "UNLOCK" SIGNAL >>>                                                               |
|           v                                                                                             |
+-----------|---------------------------------------------------------------------------------------------+
            |
            | (Connects to Main Server TCP Thread)
            v
_--=[ MAIN PAYLOAD RELEASE ]=--_




   --=[ 3.0 [ Contributors ]
           at this moment this repo it's a "one-man army", or a little more.
           This section aims to express what those who intend to help and contribute to this project will have to do.

            _-_There are two types of contributors in this repository_-_
          
              --< 1 => ::._The Core_.::

                        The Cores are the most active and deserving contributors to the entire project.
                        They have shown that they know where to put their hands without blowing everything up.
                        And for this year, more responsibility.

                        Those who will be in the future, Core at this time will have their own branch where they can apply changes with complete freedom.
                        Furthermore, being developers, they will be able to recommend mechanics or the direction to take,
                        but to be safe, all the code will be supervised.
                  
                              
              --< 2 => .__-Outriders-__.

                        Outriders are those who have made small bug fixes or added a minor or control feature
                        for which reason they will not be able to do certain actions but will still be able to contribute to the cause                      

                        Want to move from Drifter to Core? Be consistent.
                        A single commit doesn't make you an architect, it just makes you useful for a day.
              
          
                   
               
              --=[ 3.1 [ Rules ]

                    --- [ > the rules are simple and concise:

                               [-]==========================================================================[-]
                           /*
                            *
                            *    + KISS: If I have to read a manual to understand your code, I eliminate both.
                            *    + STDLIB: The Go standard library is the law. or face the Lib God and walk backwards into hell
                            *    + PERM: Touch without permission and you'll be banned from the calculator too.
                            *    + GIT: Commit clearly. "Fix stuff" isn't a description, it's a cry for help.
                            *    + BUILD: If it doesn't compile good code, your PR becomes a meme in my archive.
                            *    + VIBE: Respect the gray. If you break ASCII art, you break our friendship.    
                            *                                                                                  
                            *    [^] NO FEAR & NO DOUBT [v]                                                    
                            */                                                                                 
                               |=[ and ]=--------------------------------------------------------------------=|


   --=[ 4.0 [ License ]


         Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
         to deal in the Software without restriction, including without limitation the rights to use, copy, modify,
         merge, publish, distribute, sublicense, and/or sell copies of the Software,
         and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

                -  If you use code from other repositories or projects,
                   you must explicitly state in both the code and the readme the parts that derive from this repository.

                - If you use this tool in other tools or projects,
                  please make this repository explicit and revert to the same license present in the repository.

                - The Software is provided "as is", without warranty of any kind. In no event shall the authors be liable for any claim,
                  damages or other liability arising from the use of the software.

                - You may not impose any further restrictions on the recipients' exercise of the rights granted herein.

                - All modified versions of the Software must carry prominent notices indicating that the files have been modified and the date of each modification.
                  In the event of alterations to the code,
                  the managers of the official repositories assume no responsibility for any tampering or damage resulting from the latter.



                --=[ 5.0: Pem => [ AI not admitted ]

                      /!!_ We do not recommend the use of such technologies without human control. _!!\

                      LLMs will not be allowed in this site or in the repositories present in the FixIT-School project,
                      as there is a license and the code must be preserved and not violated for any reason,
                      not even by an LLM searching for data.


                      --- [ > NOTE:

                            If LLMs are used for code analysis or for reviewing specific areas of the repository,
                            they are fine as long as their use is not only expressly reported,
                            but also supervised in every single interaction to prevent errors from being made



               ______________________________________
      ________|            LICENSE fr. BT            |_______
      \       | _ FiXIT-School repo license          |      /
       \      | _ in the LICENSE file                |     /
       /      |______________________________________|     \
      /__________)                                (_________\
          ------------------------------------------------




   --=[ 6.0: [ Doc for code ]

         I'm finishing the website for FixIT-School so it will take a few more days to complete both,
         the documentation and the wiki but the bulk of it has been done,
         the current site sucks so we will replace it completely



   --=[ 7.0 [ Creator and other ]

           ----( BitCrucio )----
               ::. or BT .::

                > GitHub: github.com/lol1074 <
                < Email:  bitcrucio0x0[at]gmail{dot}com >
                > message: I don't know who you are, but you're a fighter < 


```
      



